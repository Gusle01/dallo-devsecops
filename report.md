# Dallo DevSecOps — 프로젝트 종합 보고서 (발표용)

> Red Team(공격) 분석과 Blue Team(방어) 검증을 하나의 파이프라인으로 결합한 **AI 기반 공격·방어 보안 분석 플랫폼**
>
> 전북대학교 SW중심대학사업단 캡스톤디자인 · 팀 달로 · 기업연계: 올포랜드

이 문서는 발표 자료 제작을 위해 프로젝트의 **구성 · 동작 원리 · 기능별 상세 · 데이터 모델 · 화면 · 기술 스택 · 보안 설계 · CI/CD**를 한 곳에 정리한 종합 보고서입니다.

---

## 1. 한눈에 보는 프로젝트

| 항목 | 내용 |
|------|------|
| **무엇** | 소스 코드(업로드/오픈소스/PR)를 받아 보안 취약점을 찾고(Red Team), LLM이 수정 코드를 만들어(Blue Team), 수정 전/후 보안성을 정량 비교하는 DevSecOps 플랫폼 |
| **차별점** | 단순 취약점 목록이 아니라 **공격 경로(Attack Plan) → 방어 경로(Defense Plan) → Before/After 근거**까지 하나의 흐름으로 제공 |
| **핵심 파이프라인** | 정적 분석 → 공격 시나리오 해석 → LLM 방어 코드 생성 → 문법/보안 재검증 → Before/After 비교 |
| **형태** | FastAPI 백엔드 + React 대시보드 + Celery/Redis 비동기 + SQLite/PostgreSQL + GitHub Actions CI/CD |
| **대표 가치** | "AI가 코드를 공격자의 눈으로 보고, 방어자의 손으로 고치고, 그 효과를 수치로 증명한다" |

### 한 줄 시연 시나리오
취약한 파이썬 코드를 붙여넣으면 → 실시간으로 취약점이 표시되고 → `레드팀 분석`을 실행하면 SQL Injection 등 취약점·공격 시나리오·CVSS가 나오고 → `LLM 패치`로 안전한 코드가 생성되며 → 문법/보안 재검증을 거쳐 → `수정 전/후 diff`와 위험도 감소율이 표시되고 → 버튼 한 번으로 GitHub PR까지 생성됩니다.

---

## 2. 배경과 문제 정의

- 최근 Claude Code의 `/security-review`, GitHub Actions 기반 자동 보안 리뷰처럼 **AI를 코드 보안 리뷰·수정 자동화**에 쓰는 흐름이 빠르게 확산.
- 그러나 대부분의 도구는 **"취약점을 찾는 것"** 에 머무름. 실제 현장에서는 다음이 더 중요함:
  1. 이 취약점이 **어떻게 악용**되는가? (공격 관점)
  2. **어떻게 고쳐야** 하는가? (방어 관점)
  3. 고친 뒤 **정말 안전해졌는가?** (검증·근거)
- **Dallo의 답**: 탐지(Red) → 수정(Blue) → 재검증(Evidence)을 한 파이프라인으로 묶어, "공격·방어·증거"를 함께 제시.

---

## 3. 핵심 개념 — Red Team / Blue Team / Before·After

| 관점 | 역할 | Dallo 구현 |
|------|------|------------|
| **Red Team** | 악용 가능한 취약점·공격 경로 식별 | Bandit/Semgrep/휴리스틱 분석, CWE/CVSS 위험도, 공격 시나리오, 악용 가능성 산정 |
| **Blue Team** | 취약점 방어·보안성 강화 | LLM 리팩토링(minimal/recommended/structural), 문법 검증, 보안 재검증 |
| **Before/After Evidence** | 수정 효과 정량 비교 | 수정 전/후 취약점 수, 제거/잔여/신규, 위험도 감소율, 리포트(전/후 diff·CWE/CVE/CVSS) |

### Attack Plan (공격 경로 구조화)
Red Team 결과는 취약점 목록이 아니라 **공격 경로**로 구조화됩니다.
```json
{
  "attack_goal": "bypass account verification for another user",
  "controlled_input": "HTTP request parameter userId",
  "trust_boundary": "HTTP request -> server-side authorization/session state",
  "vulnerable_action": "server-side verification state update",
  "attack_path": "HTTP request parameter userId -> server-side verification state update",
  "status": "OPEN"
}
```

### Defense Plan (방어 경로 연결)
Blue Team 결과는 그 공격 경로를 **어떻게 차단하는지** 연결합니다.
```json
{
  "defense_goal": "Remove request-controlled identity from account verification.",
  "strategy": "Use the authenticated server-side principal instead of request userId.",
  "validation": ["syntax_check: passed", "security_revalidation: passed"],
  "status": "BLOCKED",
  "residual_risk": "low"
}
```

대시보드 `공격/방어` 탭은 각 취약점을 `OPEN` / `MITIGATING` / `BLOCKED` / `REVIEW` 상태로 표시해 공격 경로가 방어됐는지 보여줍니다.

---

## 4. 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────┐
│                    Web Dashboard (React)                  │
│  [레드팀 분석] → [공격/방어] → [대시보드] → [취약점]        │
│  [블루팀 수정] → [의존성] → [리포트] → [이력]               │
└────────────────────────┬────────────────────────────────┘
                         │ REST API (X-API-Key 인증)
┌────────────────────────▼────────────────────────────────┐
│              FastAPI Server + Celery Worker               │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐   │
│  │  Bandit  │ │ Semgrep  │ │   LLM    │ │  Validator  │   │
│  │ (Python) │ │(다중언어)│ │(Provider)│ │ (문법/보안) │   │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬──────┘   │
│       └──────┬─────┘            │             │          │
│   [Red Team 분석]→[위험도 산정]→[Blue Team 수정]→[검증]    │
│                          │                                │
│                  SQLite / PostgreSQL + Redis              │
└─────────────────────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│               GitHub Actions CI/CD                       │
│  PR → Bandit → 파이프라인 → 테스트 → CI Gate → PR 코멘트   │
└─────────────────────────────────────────────────────────┘
```

### 구성 요소 역할
| 계층 | 모듈 | 역할 |
|------|------|------|
| **프론트엔드** | `dashboard/` (React 19 + Vite 6 + Recharts) | 코드 입력·실시간 스캔·결과 시각화·리포트·PR 연동 |
| **API 서버** | `api/server.py` (FastAPI) | 분석 요청, 조회, 인증, 리포트, apply-patch(PR) |
| **비동기 큐** | `api/celery_app.py`, `api/tasks.py` (Celery + Redis) | 무거운 분석 작업 비동기 처리 (Redis 없으면 메모리 fallback) |
| **분석기** | `analyzer/` | 정적 분석·문맥 추출·중복 제거·위험도 산정·의존성 스캔 |
| **LLM 에이전트** | `agent/` | Provider 추상화, 프롬프트, 수정안 생성, 캐시·배치 |
| **검증기** | `validator/` | 문법 검증, 보안 재검증, 테스트 실행 |
| **공통/데이터 계약** | `shared/` | 스키마, 암호화, 마스킹, red/blue 로직, CWE→CVSS 맵 |
| **DB** | `db/` (SQLAlchemy) | 분석 세션·취약점·패치 영속화 (코드 스니펫 AES-256 암호화) |
| **연동** | `integrations/`, `scripts/` | GitHub PR 코멘트, CI Gate, 키 생성 |

---

## 5. 전체 동작 흐름 (분석 파이프라인)

진입점은 `analyzer/pipeline.py`의 `execute_pipeline()`이며, 다음 순서로 동작합니다.

```
코드 입력 (대시보드 업로드 / 붙여넣기 / GitHub PR)
  │
1) 정적 분석        _run_static_analysis() → semgrep_runner.detect_and_run()
  │                  · Python = Bandit, 그 외 = Semgrep, 미설치 시 휴리스틱 fallback
  │                  → VulnerabilityReport[] (raw)
  │
2) 문맥 추출        _extract_context() → ContextExtractor
  │                  → 각 취약점의 function_code / file_imports 채움
  │
3) 중복 제거        _deduplicate() → deduplicator.deduplicate()
  │                  · rule_id 1차 그룹화 + 코드 유사도(SequenceMatcher, 0.85) 2차 클러스터
  │                  → 대표 취약점만 LLM에 전달 (비용 절감)
  │
4) 위험도 산정      _score_risk() → risk_scorer.score_vulnerabilities()
  │                  · CWE→CVSS 매핑(31종) + confidence 보정 → risk_level/cvss_score
  │                  · cve_ids, fix_priority(P1/P2/P3) 산정
  │   + Red Team 보강 (red_blue.enrich_vulnerability)
  │                  · 공격 벡터/시나리오/영향/방어전략/attack_plan
  │
5) LLM 대상 최적화 + Blue Team 수정안 생성
  │                  · scope(cve/cwe/rule)·max_targets·max_context_chars로 대상 축소
  │                  · 캐시 확인(동일 코드/취약점이면 재사용)
  │                  · DalloAgent.generate_patches() → PatchSuggestion[]
  │   (옵션) Clean Audit: 정적 분석이 clean일 때 LLM이 놓친 취약점 재검토
  │
6) 문법 검증        _validate_syntax() → SyntaxChecker
  │                  · Python = AST 파싱, 그 외 = 괄호/중괄호 매칭
  │
7) 보안 재검증      _validate_security() → SecurityChecker
  │                  · 수정 코드 + 원본 코드 재스캔 후 rule_id 비교
  │                  · 신규 취약점 0 → VERIFIED, 발생 → FAILED
  │   + Blue Team 보강 (red_blue.enrich_patch): defense_outcome/residual_risk
  │
8) Before/After 결과 조립 + 저장
                     · build_red_blue_summary(): 공격면/방어 통계, 비교(risk_reduction)
                     · AnalysisSession.to_dict() → DB 저장(save_analysis)
                     → 대시보드 / 리포트 / (옵션) GitHub PR 코멘트
```

**최종 결과 dict 핵심 키**
```python
{
  "session_id": ..., "source_code": <전체 원본>,   # 전/후 diff용
  "vulnerabilities": [VulnerabilityReport + red_team 필드],
  "patches": [PatchSuggestion + blue_team 필드],
  "llm_optimization": {...}, "llm_audit": {...},
  "red_blue_summary": {
    "red_team": {total_findings, critical_or_high, unique_cwe, affected_files},
    "blue_team": {patches_generated, patches_verified, patches_needing_review},
    "comparison": {before_total, after_total, fixed_count, remaining_count,
                   introduced_count, risk_reduction_percent},
    "attack_paths": [ {finding_id, status: OPEN|BLOCKED, ...} ]
  }
}
```

---

## 6. 기능별 상세 — 무엇을 수행하는가

### 6.1 Red Team 정적 분석 (`analyzer/`)
- **Bandit**(Python) + **Semgrep**(Java/JS/Go 등 30+ 언어, OWASP Top10·security-audit 룰셋) + **휴리스틱 fallback**(도구 미설치 시 정규식 기반).
- 탐지 결과는 `VulnerabilityReport`로 정규화: rule_id, severity, CWE, 파일/라인, 코드 스니펫 등.

### 6.2 코드 문맥 추출 (`analyzer/context_extractor.py`)
- 취약점이 포함된 **함수 전체(function_code)** 와 **import 문(file_imports)** 을 추출해, LLM에 "전체 코드가 아니라 필요한 문맥만" 전달 → 비용·속도 최적화의 핵심.

### 6.3 중복 제거 (`analyzer/deduplicator.py`)
- **1차**: `rule_id`로 그룹화. **2차**: 코드 정규화(공백/주석/줄번호 제거) 후 `SequenceMatcher` 유사도(기본 0.85)로 클러스터링.
- 클러스터마다 **severity가 가장 높은 1건을 대표**로 선정해 LLM에 전달, 나머지는 중복으로 매핑 → LLM 호출 수 절감.

### 6.4 위험도 산정 (`analyzer/risk_scorer.py`)
- **CWE→CVSS 매핑**(`shared/cwe_severity.json`, 31종, 5.3~9.8). 예: CWE-89/78/502 = 9.8, CWE-798 = 9.1.
- **confidence 보정**: LOW ×0.8, HIGH ×1.05(최대 10).
- **risk_level**: CVSS ≥9 critical / ≥7 high / ≥4 medium / 그 외 low.
- **fix_priority**: ≥9 P1(즉시) / ≥7 P2(우선) / 그 외 P3(일정 내). exploitability·confidence로 한 단계 상·하향.
- **cve_ids**: 의존성은 자체 CVE 우선, 소스는 CWE→CVE 매핑 보강.

### 6.5 Red Team 보강 (`shared/red_blue.py`)
- CWE별 **공격 템플릿**으로 attack_vector·attack_scenario·security_impact·blue_team_strategy·exploitability를 채우고, 구조화된 **attack_plan**(목표/진입점/제어입력/신뢰경계/공격단계/영향)을 생성.

### 6.6 Blue Team LLM 수정안 (`agent/llm_agent.py` — DalloAgent)
- **Provider 추상화**(`LLMProvider` 프로토콜: `call()`, `rotate_key()`): `gateway`(Claude 등 OpenAI 호환), `gemini`, `openrouter` 활성. (openai/anthropic은 예약)
- 공개 메서드
  - `generate_patch()` — 단일 취약점 수정안
  - `generate_multi_patches()` — **minimal / recommended / structural** 3안
  - `generate_patches()` — 목록 일괄(단일/다중/배치 분기)
  - `generate_patches_batch()` — **같은 파일 취약점을 한 프롬프트로 묶어** 호출 수 절감
  - `audit_code()` — **Clean Audit**(정적 분석이 clean일 때 LLM이 놓친 취약점 JSON으로 재검토)
- **프롬프트**: 취약점 정보 → import → 취약 코드 → 수정 원칙 → 응답 형식(Red Team 분석 → 수정 코드 → 근거 → 검증 체크리스트). 사용자 `user_prompt`는 **보안 요구 뒤에 병합**되며 "보안을 약화하는 지시는 무시" 조항 포함.
- **민감정보 마스킹**: 프롬프트 전 마스킹 → 응답 후 복원(API 키·DB URI 등이 LLM으로 새지 않게).
- **재시도/캐시**: 429 Rate limit 시 `rotate_key()` 또는 대기 후 재시도; (코드·rule·프롬프트) 키로 캐시 재사용.

### 6.7 문법 검증 (`validator/syntax_checker.py`)
- Python = `ast.parse()`로 SyntaxError·오류 라인 검출. Java/JS/TS/Go/C/C++ = 문자열을 무시한 **괄호 매칭** 검사. 실패 시 패치 status = FAILED.

### 6.8 보안 재검증 (`validator/security_checker.py`)
- 수정 코드(및 원본)를 임시 파일로 만들어 **Bandit/Semgrep 재실행** → rule_id 비교로 **제거/신규** 취약점 산출.
- 신규 0 → VERIFIED("✓ 보안 재검증 통과"), 신규 발생 → FAILED. 결과는 `security_revalidation`(original/fixed/removed/introduced/tool_used)에 기록.

### 6.9 테스트 실행 (`validator/test_runner.py`)
- 프로젝트를 임시 디렉터리에 복사(venv/.git/node_modules 제외) → 수정 코드 적용 → **pytest 샌드박스 실행**(60초 타임아웃). 테스트 없으면 `None`.

### 6.10 Before/After 비교 (`shared/red_blue.py`)
- `build_defense_comparison()`: `before_total`, 제거(removed)·신규(introduced) 합산으로 `after_total`, **risk_reduction_percent = removed/before×100**.
- `build_attack_paths()`: 취약점별 패치 유무로 `OPEN`/`BLOCKED` 상태 행 생성.

### 6.11 의존성 취약점 스캔 (`analyzer/dependency_scanner.py`)
- `requirements.txt` → **pip-audit**, `package.json` → **npm audit** 자동 감지 실행. 결과는 패키지·취약점(CVE·수정버전·심각도) + **SBOM**(설치 패키지 목록). 미설치 시 패키지 목록만 fallback.

### 6.12 민감정보 마스킹 (`shared/masking.py`)
- Microsoft **Presidio**(AWS 키/JWT/GitHub·Slack 토큰/주민번호 등) 기반, 미설치 시 **정규식 fallback**. 코드가 외부 LLM으로 나가기 전 민감값을 가립니다.

### 6.13 LLM 속도·비용 최적화
- 정적 분석은 전체 코드를 대상으로 하되, **LLM 수정안 생성만 선택적으로 제한**:
  `cve_scope`/`cwe_scope`/`rule_scope`(대상 유형), `max_llm_targets`(대상 수), `max_context_chars`(문맥 길이), `batch_llm`(파일 단위 배치), 캐시(동일 입력 재사용).

### 6.14 인증 + CI 보안 게이트
- 모든 데이터 API는 `X-API-Key` 인증(`api/auth.py`, 타이밍 공격 방지 비교).
- `scripts/ci_gate.py`: critical ≥1 또는 high ≥5 시 **빌드 실패**(임계값은 `.github/dallo-gate.yml`/환경변수로 조정).

### 6.15 GitHub PR 자동 생성 (`api/server.py` `/api/apply-patch`)
- 수정안을 로컬 저장 후, 토큰·레포가 있으면 **새 브랜치 생성 → 커밋 → PR 생성**.
- 입력 레포는 `owner/repo` 또는 전체 URL 모두 허용(자동 정규화), **기본 브랜치 자동 감지**(main/master), 권한 부족 시 명확한 안내. 토큰은 **저장하지 않고** 해당 요청에만 사용.

---

## 7. 데이터 모델

### 7.1 공통 스키마 (`shared/schemas.py`)
- **Enum**: `Severity`(HIGH/MEDIUM/LOW), `AnalysisTool`(bandit/sonarqube), `PatchStatus`(pending/generated/verified/failed/applied/rejected).
- **VulnerabilityReport** (정규화된 취약점): id, tool, rule_id, severity, confidence, title, description, file_path, line_number, code_snippet, function_code, file_imports, cwe_id, language, **risk_level, cvss_score, cve_ids, fix_priority, priority_label**, duplicate_group_id, **attack_vector, attack_scenario, exploitability, security_impact, blue_team_strategy, attack_plan** 등.
- **PatchSuggestion** (LLM 수정안): vulnerability_id, fixed_code, explanation, fix_type(minimal/recommended/structural), status, syntax_valid, test_passed, **security_revalidation**, defense_strategy, defense_outcome, residual_risk, defense_plan 등.
- **AnalysisSession** (1회 분석 전체): session_id, repo, pr_number, commit_sha, vulnerabilities[], patches[], total_issues, high/medium/low_count, patches_generated/verified, 시간 정보. `to_dict()`가 red_blue_summary를 포함해 직렬화.

### 7.2 DB 스키마 (`db/models.py`, SQLAlchemy)
```
AnalysisRun (분석 세션)  1 ── N  Vulnerability (취약점)  1 ── N  Patch (수정안)
```
- **AnalysisRun**: session_id(UNIQUE), repo, pr_number, commit_sha, branch, total/high/medium/low, patches_generated/verified, **source_code(암호화 저장)**, 시간.
- **Vulnerability**: vuln_id, run_id(FK), tool, rule_id, severity, confidence, title, description, cwe_id, file_path, line_number, code_snippet, function_code.
- **Patch**: vulnerability_id(FK), fixed_code, explanation, fix_type, status, syntax_valid, test_passed, 시간.
- DB는 `DATABASE_URL` 있으면 PostgreSQL, 없으면 **SQLite 자동 폴백**. 코드 스니펫/원본은 **AES-256(Fernet)** 으로 암호화 저장.

---

## 8. 웹 대시보드 (화면별 기능)

React 19 + Vite 6 + Recharts. 로그인(`X-API-Key`) 후 8개 탭으로 구성됩니다.

| 탭(메뉴) | 컴포넌트 | 수행 기능 |
|---------|----------|----------|
| **레드팀 분석** | `AnalyzeView` | 코드 붙여넣기/파일·폴더 업로드, **실시간 스캔**(타이핑 중 빠른 탐지), LLM 옵션(다중 패치/일괄/AI 정밀점검/보안 재검증/scope/모델), 분석 실행, 결과(취약점·수정안·**전/후 diff**), **open report**, **git push(PR)** |
| **공격/방어** | `RedBlueView` | Red/Blue 요약 지표, 공격 표면·방어 태세, 공격 경로 상태(OPEN/BLOCKED), 레드팀 탐지·블루팀 조치 목록 |
| **대시보드** | `StatsCards`+`FileChart`+`TypeChart` | 심각도별 통계 카드, 파일별 막대 차트, 유형별 도넛 차트 |
| **취약점** | `VulnTable` | 취약점 표(심각도/CVSS/규칙/제목/파일/라인/**CWE→MITRE·CVE→NVD 링크**), 행 펼침 상세 |
| **블루팀 수정** | `PatchView` | 수정안 목록, 펼치면 설명·**전/후 diff(split/unified)**·문법/보안 재검증 배지 |
| **의존성** | `DependencyView` | requirements/package 스캔, 취약 패키지 표(CVE·수정버전), SBOM |
| **리포트** | `ReportView` | 인쇄용 HTML 리포트 생성(새 창)·Markdown 다운로드 |
| **이력** | `HistoryView` | 세션 표 + **세션별 추이 통합 차트**(막대=심각도별 탐지, 선=패치 초안/검증) |

### UI/UX 디자인
- **라이트 테마**: 따뜻한 오프화이트 배경, 흰 카드, 부드러운 그림자, 에메랄드(`#0a7d56`) 악센트.
- **폰트**: 본문/한글 **Pretendard**, 제목·숫자 **Fraunces**(세리프), 코드 **JetBrains Mono**.
- **한글화**: 모든 메뉴/기능 토글/표/상태 라벨 한글.
- **리포트**: 화면과 동일한 라이트 테마, 탐지 표에 **CWE/CVE/CVSS**, 블루팀 수정마다 **수정 전/후 diff**(빨강 삭제·초록 추가)와 보안 재검증 결과 — HTML/Markdown 모두 지원.

---

## 9. API 엔드포인트 (요약)

데이터 엔드포인트는 모두 `X-API-Key` 인증 필요.

| Method | Endpoint | 설명 |
|--------|----------|------|
| GET | `/api/stats` | 대시보드 통계 |
| GET | `/api/vulnerabilities`(`/by-file`,`/by-type`) | 취약점 목록·집계 |
| GET | `/api/patches` | 수정안 목록 |
| GET | `/api/sessions`(`/{id}`) | 분석 이력·상세 |
| POST | `/api/analyze` · GET `/api/analyze/{job_id}` | 분석 실행(비동기)·진행 상태 |
| POST | `/api/quick-scan`(`-project`) | 정규식 기반 실시간 스캔 |
| POST | `/api/apply-patch` | 수정안 적용 + GitHub PR 생성 |
| GET/POST | `/api/dependencies`(`/scan`) | 의존성 취약점 스캔 |
| GET | `/api/report/generate`·`/preview`·`/download/{f}` | 리포트 생성·미리보기·다운로드 |
| GET | `/dashboard` · `/docs` | 대시보드(인증 불필요)·API 문서 |

---

## 10. 기술 스택

| 구분 | 기술 |
|------|------|
| 정적 분석 | Bandit 1.7+, Semgrep 1.50+, SonarQube 10 |
| AI/LLM | API Gateway/Claude(기본), Google Gemini, OpenRouter/Qwen |
| 민감정보 | Microsoft Presidio + 정규식 fallback |
| 백엔드 | Python 3.11+, FastAPI, Celery, SQLAlchemy |
| 비동기 큐 | Celery + Redis |
| 프론트엔드 | React 19, Recharts, Vite 6, Pretendard/Fraunces/JetBrains Mono |
| DB | SQLite(개발) / PostgreSQL 16(운영) |
| 암호화 | AES-256(Fernet), 환경변수 기반 키 |
| CI/CD | GitHub Actions + CI Gate(임계값 빌드 차단) |
| 컨테이너 | Docker, Docker Compose |

---

## 11. 설정과 환경

### 11.1 파이프라인 설정 (`config/config.yaml`)
- **Deduplication**: enabled, similarity_threshold(0.85)
- **Risk Scoring**: enabled
- **Policy Filter**: enabled(기본 off), exclude_rules/min_severity/exclude_cwe
- **LLM**: primary_provider, batch_size(5), cache_ttl_days(7)
- **LLM Optimization**: max_targets(10), max_context_chars(2400), batch_enabled, 기본 cwe_scope = `CWE-89,78,79,288,502,22,798`
- **Semgrep**: 룰셋(auto, security-audit, owasp-top-ten, java, findsecbugs, custom), timeout(120s)
- **CI Gate**: critical_threshold(1), high_threshold(5)

### 11.2 주요 환경변수
| 변수 | 의미 |
|------|------|
| `DALLO_ENCRYPTION_KEY` | DB 암호화 키(**미설정 시 시작 불가, fail-fast**) |
| `DALLO_API_KEYS` | API 인증 키(미설정 시 인증 스킵+경고) |
| `LLM_PRIMARY_PROVIDER` / `GATEWAY_API_KEY` / `GEMINI_API_KEY` / `OPENROUTER_API_KEY` | LLM 프로바이더·키 |
| `CELERY_BROKER_URL` / `CELERY_RESULT_BACKEND` | Celery(Redis) |
| `DATABASE_URL` | 비우면 SQLite |
| `DALLO_GATE_CRITICAL_THRESHOLD` / `DALLO_GATE_HIGH_THRESHOLD` | CI Gate 임계값 |

### 11.3 Graceful Degradation (외부 의존성 없어도 동작)
| 의존성 | 미설치/미실행 시 |
|--------|----------------|
| Redis | 메모리 작업 관리 + 메모리 캐시로 fallback |
| Presidio | 정규식 마스킹으로 fallback |
| DALLO_API_KEYS | 인증 스킵 + 경고(개발용) |
| PostgreSQL | SQLite 자동 사용 |

---

## 12. 보안 설계

- **저장 데이터 암호화**: 코드 스니펫/원본은 AES-256(Fernet), 키는 환경변수로만(하드코딩 금지). 키 미설정 시 **fail-fast**.
- **민감정보 마스킹**: LLM 호출 전 마스킹 → 응답 후 복원.
- **API 인증**: `X-API-Key`, 타이밍 공격 방지 비교.
- **LLM 프롬프트 가드**: 사용자 지시가 보안을 약화시키면 무시.
- **GitHub 토큰**: 브라우저에 저장하지 않고 요청 1회용으로만 사용.
- **CI 보안 게이트**: critical/high 임계값 초과 시 빌드 차단.

---

## 13. CI/CD 파이프라인

PR(`.py` 변경) 발생 시 GitHub Actions가 자동 실행:
1. Bandit 정적 분석(취약점 있어도 리포트 생성)
2. 전체 파이프라인(Bandit → 중복 제거 → 위험도 → LLM(키 있을 때))
3. 유닛 테스트 96개
4. **보안 게이트**(Critical ≥1 또는 High ≥5 → 빌드 실패)
5. **PR 코멘트** 자동 게시(`integrations/pr_commenter.py`)

---

## 14. 테스트 (총 96개)

| 영역 | 파일 | 개수 |
|------|------|------|
| Bandit/문맥/파서 | `test_bandit_runner`/`test_context_extractor`/`test_llm_parser` | 10/5/8 |
| 문법/API/암호화/인증 | `test_syntax_checker`/`test_api_server`/`test_encryption`/`test_auth` | 6/8/10/6 |
| 중복·위험도/캐시·배치 | `test_dedup_risk`/`test_cache_batch` | 10/10 |
| 마스킹/CI Gate/통합 | `test_sensitive_masker`/`test_ci_gate`/`test_pipeline_integration` | 12/7/4 |

```bash
DALLO_ENCRYPTION_KEY=test-key python -m pytest tests/ -v
```

---

## 15. 프로젝트 구조 (요약)

```
dallo-devsecops/
├── analyzer/      # 정적 분석·문맥추출·중복제거·위험도·의존성 (pipeline.py = 8단계 통합)
├── agent/         # DalloAgent, provider/factory, 캐시·배치·프롬프트
├── validator/     # syntax_checker, security_checker, test_runner
├── api/           # server.py(FastAPI), auth, celery_app, tasks
├── dashboard/     # React 대시보드 (src/components/*, api/client.js)
├── db/            # models, service, key_provider (SQLAlchemy)
├── shared/        # schemas, red_blue, encryption, masking, cwe_severity.json
├── reports/       # report_generator.py (HTML/Markdown 리포트)
├── integrations/  # github_client, pr_commenter
├── scripts/       # run_analysis, ci_gate, post_pr_comment, generate_encryption_key
├── config/        # config.yaml, bandit.yml, sonar-project.properties
├── tests/ test_targets/ docker/ .github/
└── start.py       # 원클릭 실행
```

---

## 16. 향후 계획 — 정확도 측정

`test_targets/`와 WebGoat류 샘플을 baseline으로, 이후 실제 오픈소스로 다음 지표를 측정:

| 지표 | 의미 |
|------|------|
| Precision / Recall / F1 | 탐지 정밀도·재현율·조화평균 |
| False Positive / Negative | 오탐·미탐 |
| Patch Success Rate | 수정안이 문법·보안 재검증을 통과한 비율 |
| Risk Reduction | 수정 전/후 critical/high 감소율 |

---

## 17. 발표 시 강조 포인트

1. **공격→방어→증거를 한 파이프라인으로** — 단순 탐지 도구와의 결정적 차별점.
2. **공격 경로(Attack Plan) ↔ 방어 경로(Defense Plan)** 의 구조화 — "왜 위험하고, 어떻게 막는가"를 시각화.
3. **검증 가능한 수정** — LLM 수정안을 문법+보안 재검증으로 다시 스캔해 **수치(위험도 감소율)** 로 증명.
4. **실용적 엔지니어링** — 중복 제거·문맥 추출·배치·캐시로 LLM 비용 최적화, Redis/Presidio/PostgreSQL 없는 환경에서도 동작(Graceful Degradation).
5. **보안 의식이 내장된 도구** — 저장 암호화·민감정보 마스킹·API 인증·CI 보안 게이트.
6. **현장 연결** — 버튼 한 번으로 GitHub PR 생성, CI에서 PR 코멘트·게이트로 개발 흐름에 통합.

---

## 18. 팀 구성

| 이름 | 역할 | 담당 |
|------|------|------|
| 박영주 | 팀장 / AI | LLM 코드 분석·리팩토링 모듈 |
| 이준수 | 백엔드 / DevSecOps | 정적 분석, CI/CD, API, 대시보드, DB |
| 임해안 | 프론트엔드 / 데이터 | 웹 대시보드 UI, DB 설계, 시각화 |

**지도교수**: 김윤경(SW중심대학사업단) · **참여기업**: 올포랜드(담당 김민솔)

---

*이 문서는 발표 자료 제작용 종합 정리본입니다. 세부 변경 이력은 `update.md`, 설치/실행은 `README.md`를 참고하세요.*
