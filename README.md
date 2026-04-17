# Dallo DevSecOps

> LLM 에이전트 기반 소스코드 보안 취약점 분석 및 리팩토링 제안 시스템

**전북대학교 SW중심대학사업단 캡스톤디자인 | 팀 달로 | 기업연계: 올포랜드**

## Overview

코드를 업로드하면 보안 취약점을 자동으로 탐지하고, AI가 수정된 코드를 제안하는 DevSecOps 플랫폼입니다.

### 핵심 기능
- **정적 분석**: Bandit(Python) + Semgrep(Java, JavaScript, Go 등 30개+ 언어)
- **AI 수정안 생성**: Gemini / OpenAI / Claude API로 취약점별 수정 코드 자동 생성
- **코드 검증**: AI가 생성한 코드의 문법 검사 + 테스트 실행
- **웹 대시보드**: 코드 업로드 → 실시간 분석 → 결과 시각화
- **GitHub CI/CD**: PR 발생 시 자동 분석 + PR 코멘트로 결과 제공
- **DB 이력 관리**: 분석 세션별 취약점/패치 이력 저장 + 추이 차트

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Web Dashboard                         │
│  [코드 업로드] → [실시간 분석] → [결과 시각화/Diff 비교]    │
└────────────────────────┬────────────────────────────────┘
                         │ REST API
┌────────────────────────▼────────────────────────────────┐
│                   FastAPI Server                         │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │  Bandit   │  │ Semgrep  │  │   LLM    │  │Validator│  │
│  │ (Python)  │  │(다중언어) │  │(Gemini)  │  │(문법/  │  │
│  │          │  │          │  │          │  │ 테스트) │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───┬────┘  │
│       └──────┬──────┘             │             │       │
│              ▼                    ▼             ▼       │
│     VulnerabilityReport → PatchSuggestion → Verified    │
│              │                    │             │       │
│              └────────────┬──────┘─────────────┘       │
│                           ▼                             │
│                     SQLite / PostgreSQL                  │
└─────────────────────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│               GitHub Actions CI/CD                       │
│  PR 발생 → Bandit 분석 → LLM 수정안 → 테스트 → PR 코멘트  │
└─────────────────────────────────────────────────────────┘
```

## Security Notice

> **암호화 키 관리**: DB 코드 스니펫은 AES-256으로 암호화됩니다.
> 암호화 키는 반드시 환경변수(`DALLO_ENCRYPTION_KEY`)로 설정해야 하며,
> 소스 코드에 하드코딩하면 안 됩니다.
>
> ```bash
> # 키 생성
> python scripts/generate_encryption_key.py
> # 출력된 키를 .env 파일에 설정
> ```
>
> **경고**: 이전 커밋 히스토리에 개발용 기본 키(`dallo-devsecops-default-key-*`)가
> 포함되어 있습니다. 운영 환경에서는 반드시 새 키를 생성하여 사용하고,
> 기존 데이터는 새 키로 재암호화(키 로테이션)하세요.

## Quick Start

```bash
# 1. 클론
git clone https://github.com/JUNSU0202/dallo-devsecops.git
cd dallo-devsecops

# 2. 가상환경 + 의존성 설치
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 3. 환경변수 설정
cp .env.example .env
# .env 파일에 GEMINI_API_KEY 설정

# 4. 원클릭 실행
python start.py
```

### Celery Worker (선택사항 — Redis 필요)

```bash
# Redis 실행 (Docker)
docker run -d --name dallo-redis -p 6379:6379 redis:7-alpine

# Celery worker 실행 (별도 터미널)
celery -A api.celery_app worker --loglevel=info
```

> Redis가 없으면 자동으로 메모리 기반 fallback으로 동작합니다.

서버가 시작되면:
- **대시보드**: http://localhost:8000/dashboard
- **API 문서**: http://localhost:8000/docs

## Project Structure

```
dallo-devsecops/
│
├── analyzer/                    # 정적 분석 모듈
│   ├── bandit_runner.py         # Bandit 분석기 (Python)
│   ├── semgrep_runner.py        # Semgrep 분석기 (다중 언어)
│   ├── sonar_runner.py          # SonarQube 연동
│   ├── context_extractor.py     # 취약점 주변 코드 문맥 추출
│   └── result_parser.py         # 분석 결과 파싱/병합
│
├── agent/                       # LLM 에이전트
│   └── llm_agent.py             # Gemini/OpenAI/Claude API 호출 + 응답 파싱
│
├── validator/                   # 코드 검증
│   ├── syntax_checker.py        # 문법 검사 (AST 파싱)
│   └── test_runner.py           # 샌드박스 테스트 실행
│
├── api/                         # REST API 서버
│   └── server.py                # FastAPI (분석 실행, 결과 조회, 대시보드 서빙)
│
├── dashboard/                   # 웹 대시보드 (React)
│   └── src/components/
│       ├── AnalyzeView.jsx      # 코드 업로드 + 실시간 분석
│       ├── StatsCards.jsx       # 통계 카드
│       ├── VulnTable.jsx        # 취약점 목록 테이블
│       ├── PatchView.jsx        # AI 수정안 + Diff 비교
│       ├── FileChart.jsx        # 파일별 취약점 차트
│       ├── TypeChart.jsx        # 유형별 파이 차트
│       └── HistoryView.jsx      # 분석 이력 + 추이 차트
│
├── db/                          # 데이터베이스
│   ├── models.py                # SQLAlchemy ORM (AnalysisRun, Vulnerability, Patch)
│   └── service.py               # DB 저장/조회 서비스
│
├── integrations/                # GitHub 연동
│   ├── github_client.py         # GitHub API 클라이언트
│   └── pr_commenter.py          # PR 코멘트 자동 작성
│
├── shared/                      # 공통 데이터 구조
│   └── schemas.py               # VulnerabilityReport, PatchSuggestion, AnalysisSession
│
├── scripts/                     # 실행 스크립트
│   ├── run_analysis.py          # CLI 전체 파이프라인
│   └── post_pr_comment.py       # GitHub Actions PR 코멘트 게시
│
├── tests/                       # 유닛 테스트 (35개)
│   ├── test_bandit_runner.py
│   ├── test_context_extractor.py
│   ├── test_llm_parser.py
│   ├── test_syntax_checker.py
│   └── test_api_server.py
│
├── test_targets/                # 취약점 테스트 샘플
│   ├── sql_injection.py         # SQL Injection (Python)
│   ├── command_injection.py     # Command Injection (Python)
│   ├── insecure_crypto.py       # Weak Cryptography (Python)
│   ├── hardcoded_secrets.py     # Hardcoded Credentials (Python)
│   ├── xss_vulnerable.py        # XSS (Python)
│   ├── insecure_auth.py         # Insecure Auth (Python)
│   ├── insecure_deserialization.py # Deserialization (Python)
│   ├── VulnerableApp.java       # Java 취약점 샘플
│   ├── vulnerable_app.js        # JavaScript 취약점 샘플
│   └── vulnerable_app.go        # Go 취약점 샘플
│
├── .github/workflows/
│   └── security-analysis.yml    # GitHub Actions CI/CD
├── docker/
│   └── docker-compose.yml       # SonarQube + PostgreSQL
├── config/
│   ├── bandit.yml
│   └── sonar-project.properties
├── start.py                     # 원클릭 실행 스크립트
└── requirements.txt
```

## Tech Stack

| 구분 | 기술 |
|------|------|
| **정적 분석** | Bandit 1.7+, Semgrep 1.50+, SonarQube 10 |
| **AI/LLM** | Google Gemini 2.5 Flash, OpenAI GPT-4o, Anthropic Claude |
| **백엔드** | Python 3.11+, FastAPI, SQLAlchemy |
| **프론트엔드** | React, Recharts, Vite |
| **데이터베이스** | SQLite (개발) / PostgreSQL (운영) |
| **CI/CD** | GitHub Actions |
| **컨테이너** | Docker, Docker Compose |

## API Endpoints

| Method | Endpoint | 설명 |
|--------|----------|------|
| GET | `/api/stats` | 대시보드 통계 |
| GET | `/api/vulnerabilities` | 취약점 목록 (필터: severity, tool, file_path) |
| GET | `/api/vulnerabilities/by-file` | 파일별 취약점 집계 |
| GET | `/api/vulnerabilities/by-type` | 유형별 취약점 집계 |
| GET | `/api/patches` | AI 수정 제안 목록 |
| GET | `/api/sessions` | 분석 세션 이력 |
| POST | `/api/analyze` | 코드 분석 실행 (비동기) |
| GET | `/api/analyze/{job_id}` | 분석 진행 상태 조회 |
| GET | `/dashboard` | 웹 대시보드 |

## Pipeline Flow

```
1. 코드 입력 (대시보드 업로드 or GitHub PR)
       │
2. 정적 분석 (Bandit + Semgrep)
       │ → 취약점 탐지 (SQL Injection, XSS, Command Injection 등)
       │
3. 코드 문맥 추출
       │ → 취약점 포함 함수, import문, 주변 코드
       │
4. LLM 수정안 생성 (Gemini API)
       │ → 보안이 강화된 수정 코드 + 수정 근거
       │
5. 코드 검증
       │ → 문법 검사 (AST) + 테스트 실행 (샌드박스)
       │
6. 결과 제공
       ├→ 대시보드: 실시간 표시 + Diff 비교
       ├→ GitHub PR: 코멘트로 자동 게시
       └→ DB: 이력 저장 + 추이 분석
```

## Team

| 이름 | 역할 | 담당 |
|------|------|------|
| 박영주 | 팀장 / AI | LLM 코드 분석 및 리팩토링 모듈 |
| 이준수 | 백엔드 / DevSecOps | 정적 분석, CI/CD, API, 대시보드, DB |
| 임해안 | 프론트엔드 / 데이터 | 웹 대시보드 UI, DB 설계, 시각화 |

**지도교수**: 김윤경 (SW중심대학사업단)
**참여기업**: 올포랜드 (담당: 김민솔)
