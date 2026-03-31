# 달로 (Dallo) - DevSecOps Code Analysis System

> LLM 에이전트 기반 소스코드 보안 취약점 분석 및 리팩토링 제안 시스템

## 프로젝트 개요

GitHub Pull Request 발생 시 자동으로 정적 분석을 수행하고,
LLM이 보안 취약점에 대한 수정 코드를 생성하여 PR 코멘트로 제안하는 DevSecOps 파이프라인

## 시스템 흐름

```
GitHub PR 발생
  → GitHub Actions 트리거
    → 정적 분석 (SonarQube + Bandit)
      → 코드 문맥 추출
        → LLM 수정안 생성
          → 코드 검증 (빌드/테스트)
            → PR 코멘트 결과 제공
              → DB 저장
```

## 프로젝트 구조

```
dallo-devsecops/
├── .github/
│   └── workflows/
│       └── security-analysis.yml    # GitHub Actions 워크플로우
├── analyzer/
│   ├── __init__.py
│   ├── bandit_runner.py             # Bandit 정적 분석 실행
│   ├── sonar_runner.py              # SonarQube 분석 실행
│   ├── context_extractor.py         # 취약점 주변 코드 문맥 추출
│   └── result_parser.py             # 분석 결과 파싱/정규화
├── agent/
│   ├── __init__.py
│   ├── llm_client.py                # LLM API 클라이언트
│   ├── prompt_builder.py            # 프롬프트 생성
│   └── patch_generator.py           # 코드 패치 생성
├── validator/
│   ├── __init__.py
│   ├── syntax_checker.py            # 문법 검사
│   └── test_runner.py               # 테스트 실행 및 검증
├── integrations/
│   ├── __init__.py
│   ├── github_client.py             # GitHub API 연동
│   └── pr_commenter.py              # PR 코멘트 자동 작성
├── db/
│   ├── __init__.py
│   ├── models.py                    # DB 모델 정의
│   └── migrations/
├── test_targets/                    # 테스트용 취약 코드 샘플
│   ├── sql_injection.py
│   ├── xss_vulnerable.py
│   ├── hardcoded_secrets.py
│   ├── insecure_crypto.py
│   ├── command_injection.py
│   └── README.md
├── tests/
│   ├── test_bandit_runner.py
│   ├── test_context_extractor.py
│   └── test_pr_commenter.py
├── docker/
│   └── docker-compose.yml           # SonarQube + PostgreSQL
├── config/
│   ├── bandit.yml                   # Bandit 설정
│   └── sonar-project.properties     # SonarQube 프로젝트 설정
├── scripts/
│   └── run_analysis.py              # 전체 분석 파이프라인 실행 스크립트
├── requirements.txt
├── .gitignore
└── README.md
```

## 기술 스택

| 구분 | 기술 |
|------|------|
| 정적 분석 | SonarQube, Bandit |
| AI/LLM | OpenAI GPT / Google Gemini / Anthropic Claude |
| 백엔드 | Python |
| CI/CD | GitHub Actions |
| DB | PostgreSQL |
| 컨테이너 | Docker, Docker Compose |

## 팀 달로

| 이름 | 역할 | 담당 |
|------|------|------|
| 박영주 | 팀장 / AI | LLM 코드 분석 및 리팩토링 모듈 |
| 이준수 | 백엔드 / DevSecOps | 정적 분석 환경, CI/CD, PR 자동화 |
| 임해안 | 프론트엔드 / 데이터 | 웹 대시보드, DB 설계, 시각화 |

## 시작하기

```bash
# 1. 의존성 설치
pip install -r requirements.txt

# 2. SonarQube 실행 (Docker)
cd docker && docker-compose up -d

# 3. Bandit 단독 테스트
bandit -r test_targets/ -f json -o reports/bandit_report.json

# 4. 전체 파이프라인 실행
python scripts/run_analysis.py --target test_targets/
```
