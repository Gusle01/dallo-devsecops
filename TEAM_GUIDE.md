# 팀원 연동 가이드

> 3명이 독립적으로 개발하면서도 코드가 자연스럽게 연결되도록 하는 구조입니다.

## 전체 데이터 흐름

```
이준수 (분석)          박영주 (AI)              임해안 (프론트/DB)
─────────────        ──────────────         ──────────────

Bandit/SonarQube     LLM API 호출            React 대시보드
     │                    │                       │
     ▼                    ▼                       ▼
VulnerabilityReport → DalloAgent →          FastAPI 서버
(shared/schemas.py)  PatchSuggestion →      (api/server.py)
     │               (shared/schemas.py)         │
     ▼                    │                       ▼
PR 코멘트 게시            │                  DB 저장/조회
(pr_commenter.py)         ▼                  (db/models.py)
                    PR 코멘트에 포함
```

## 공통 규칙

### 1. 데이터는 반드시 shared/schemas.py 를 통해 주고받기

```python
from shared.schemas import VulnerabilityReport, PatchSuggestion, AnalysisSession
```

이 3개 클래스가 팀원 간 데이터 계약입니다.
필드를 추가/변경하려면 팀 전체 공유 후 수정하세요.

### 2. 브랜치 전략

```
main                ← 안정 버전만
├── dev             ← 통합 테스트용
├── feat/analyzer   ← 이준수 작업 브랜치
├── feat/agent      ← 박영주 작업 브랜치
└── feat/dashboard  ← 임해안 작업 브랜치
```

---

## 이준수 → 박영주 연동

### 이준수가 제공하는 것
분석 결과를 `VulnerabilityReport` 리스트로 만들어줍니다:

```python
# 이준수 코드 (analyzer → agent 연결)
from analyzer.bandit_runner import run_bandit_analysis
from analyzer.context_extractor import ContextExtractor
from shared.schemas import VulnerabilityReport

result = run_bandit_analysis("test_targets/")
extractor = ContextExtractor()

vuln_reports = []
for vuln in result.vulnerabilities:
    ctx = extractor.extract(vuln)
    report = VulnerabilityReport(
        id=f"vuln_{vuln.rule_id}_{vuln.line_number}",
        tool=vuln.tool,
        rule_id=vuln.rule_id,
        severity=vuln.severity,
        confidence=vuln.confidence,
        title=vuln.title,
        description=vuln.description,
        file_path=vuln.file_path,
        line_number=vuln.line_number,
        code_snippet=vuln.code_snippet,
        function_code=ctx.full_function,
        file_imports=ctx.file_imports,
        cwe_id=vuln.cwe_id,
    )
    vuln_reports.append(report)
```

### 박영주가 구현할 것
`agent/llm_agent.py`의 `DalloAgent` 클래스:

```python
from agent.llm_agent import DalloAgent

agent = DalloAgent(api_key="...", model="gpt-4")
patches = agent.generate_patches(vuln_reports)
# → list[PatchSuggestion] 반환
```

구현해야 할 메서드:
- `_build_prompt()` — 프롬프트 구성 (템플릿은 이미 작성됨)
- `_call_llm()` — OpenAI/Gemini/Claude API 호출
- `_parse_response()` — 응답에서 코드와 설명 추출

---

## 이준수 → 임해안 연동

### 이준수가 제공하는 것
분석 결과를 JSON으로 저장합니다:

```bash
# reports/bandit_report.json 자동 생성됨
python scripts/run_analysis.py --target test_targets/ --json-output reports/full_result.json
```

### 임해안이 사용하는 것

**방법 1: API 서버로 조회**
```bash
pip install fastapi uvicorn
uvicorn api.server:app --reload --port 8000

# 브라우저에서 확인
# http://localhost:8000/api/stats
# http://localhost:8000/api/vulnerabilities
# http://localhost:8000/api/vulnerabilities?severity=HIGH
# http://localhost:8000/api/vulnerabilities/by-file
# http://localhost:8000/api/vulnerabilities/by-type
```

**방법 2: DB에 직접 저장**
```python
from db.models import init_db, SessionLocal, Vulnerability, AnalysisRun

# 테이블 생성
init_db()

# 데이터 저장
with SessionLocal() as session:
    run = AnalysisRun(
        session_id="session_001",
        repo="dallo/devsecops",
        pr_number=1,
        commit_sha="abc123",
        total_issues=23,
    )
    session.add(run)
    session.commit()
```

### 대시보드 페이지 구성 (제안)
1. **메인 대시보드**: 취약점 통계 요약 (GET /api/stats)
2. **취약점 목록**: 필터/정렬 가능한 테이블 (GET /api/vulnerabilities)
3. **파일별 분포**: 차트 (GET /api/vulnerabilities/by-file)
4. **수정 제안**: Diff 비교 뷰 (GET /api/patches) — 박영주 연동 후
5. **분석 이력**: 과거 분석 기록 (GET /api/sessions)

---

## 박영주 → 이준수 연동 (수정안 검증)

박영주가 생성한 PatchSuggestion을 이준수가 검증합니다:

```python
# 이준수 코드 (validator)
from shared.schemas import PatchSuggestion

def verify_patch(patch: PatchSuggestion) -> PatchSuggestion:
    """AI 수정 코드 검증"""
    # 1. 문법 검사
    try:
        compile(patch.fixed_code, "<patch>", "exec")
        patch.syntax_valid = True
    except SyntaxError:
        patch.syntax_valid = False
        patch.status = "failed"
        return patch

    # 2. (향후) 테스트 실행
    # patch.test_passed = run_tests(patch.fixed_code)

    patch.status = "verified" if patch.syntax_valid else "failed"
    return patch
```

검증 완료된 수정안은 PR 코멘트에 포함됩니다.

---

## 파일 구조 (팀원별 담당)

```
dallo-devsecops/
├── shared/
│   └── schemas.py              ← 공통 (3명 공유)
│
├── analyzer/                   ← 이준수
│   ├── bandit_runner.py        ✅
│   ├── sonar_runner.py         ✅
│   ├── context_extractor.py    ✅
│   └── result_parser.py        ✅
├── integrations/               ← 이준수
│   ├── github_client.py        ✅
│   └── pr_commenter.py         ✅
├── validator/                  ← 이준수
│   ├── syntax_checker.py       ⏳ (구현 예정)
│   └── test_runner.py          ⏳ (구현 예정)
├── scripts/                    ← 이준수
│   ├── run_analysis.py         ✅
│   └── post_pr_comment.py      ✅
├── .github/workflows/          ← 이준수
│   └── security-analysis.yml   ✅
│
├── agent/                      ← 박영주
│   └── llm_agent.py            ⏳ (인터페이스만 정의됨)
│
├── api/                        ← 임해안
│   └── server.py               ✅ (기본 엔드포인트)
├── db/                         ← 임해안
│   └── models.py               ✅ (테이블 구조)
│
├── docker/                     ← 공통
│   └── docker-compose.yml      ✅
├── config/                     ← 공통
│   ├── bandit.yml              ✅
│   └── sonar-project.properties ✅
└── test_targets/               ← 공통
    ├── sql_injection.py        ✅
    ├── xss_vulnerable.py       ✅
    ├── hardcoded_secrets.py    ✅
    ├── insecure_crypto.py      ✅
    └── command_injection.py    ✅
```
