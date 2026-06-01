# Dallo DevSecOps 변경 내역

## 2026-06-01 (2차 패치 — diff/Defense 안정화 및 성능 개선)

### 1. 스캔 후 화면이 검게 변하는 버그 수정 (React 크래시)

- 문제: 스캔 완료 직후 결과를 그리는 순간 화면 전체가 검게 변함(렌더 도중 런타임 예외 → React 트리 언마운트).
- 원인: 결과 렌더 컴포넌트 `ResultView`는 `result`만 prop으로 받는데, diff 합성 코드에서 부모(`AnalyzeView`)의 상태인 `analyzedSource`/`code`를 직접 참조해 `ReferenceError`가 발생함. 빌드는 통과하지만 런타임에서만 터지는 종류.
- 수정: 전체 원본 소스를 `ResultView`에 `source` prop으로 전달하도록 변경하고, diff 합성부가 그 prop을 사용하도록 정리함.
- 수정 파일: `dashboard/src/components/AnalyzeView.jsx`

### 2. diff를 "전체 파일 좌우 비교"로 (redscan)

- 문제: diff가 취약 함수/스니펫 단위라, 전체 코드 맥락에서 어디가 바뀌었는지 보기 어려웠음.
- 수정: 전체 원본에 LLM 패치(보통 함수 단위 + import 추가)를 합성해 "전체 수정 파일"을 만드는 `buildFixedFile()`를 추가함. `line_number`로 취약 함수 블록을 찾아 교체하고, 새로 추가된 top-level import는 상단으로 끌어올리며, 클래스 메서드 들여쓰기에 맞춰 재정렬함(블록 미탐색 시 해당 라인만 폴백 교체).
- 수정: redscan 결과의 `DiffView`에 좌측=전체 원본, 우측=합성한 전체 수정 파일을 전달해 GitHub split(정렬 빈줄 포함)로 표시함.
- 수정 파일: `dashboard/src/utils/diff.js`, `dashboard/src/components/AnalyzeView.jsx`

### 3. diff 렌더링 성능 개선 (대용량 파일 렉 제거)

- 문제: 전체 파일을 diff할 때 코드가 크면 렌더가 오래 걸리고 렉이 걸렸음.
- 원인: `(n+1)×(m+1)` LCS 행렬을 통째로 계산(O(n·m)), 게다가 통계(`diffStats`)와 뷰(`diffSplit`)가 각각 LCS를 돌려 패치당 2회·렌더마다 반복, 메모이즈 없음.
- 수정: 공통 prefix/suffix를 먼저 잘라내고 변경된 가운데 영역에만 LCS를 적용함(패치는 함수 하나만 바꾸므로 실측 비용이 변경부 크기에 비례). 거대 변경부는 상한 초과 시 폴백해 프리즈를 방지함.
- 수정: `DiffView`에서 diff를 `useMemo`로 1회만 계산하고 split·통계를 그 결과에서 파생함. `buildFixedFile` 합성은 `PatchDiff` 컴포넌트로 분리해 입력이 바뀔 때만 재계산하도록 함.
- 효과: 5,000줄/1줄 변경 기준 diff 계산 시간 약 680ms → 1ms (기존 알고리즘과 출력 동일성 검증 완료).
- 수정 파일: `dashboard/src/utils/diff.js`, `dashboard/src/components/DiffView.jsx`, `dashboard/src/components/AnalyzeView.jsx`

### 4. Findings/Defense 탭이 비어 보이는 문제 수정 (DB 폴백)

- 문제: 스캔 후 Stats 탭은 건수(예: 4건)가 나오는데 Findings 탭은 "NO RECORDS", Defense 탭은 "NO PATCHES"로 비어 보임.
- 원인: `/api/stats`는 `full_result.json`이 없으면 DB(`get_stats`)로 폴백하지만, `/api/vulnerabilities`·`/api/patches`는 DB 폴백이 없어 빈 bandit 리포트로 떨어짐. 분석은 DB에 저장되는데 이 엔드포인트들이 DB를 안 읽었음.
- 수정: `/api/vulnerabilities`·`/api/patches`도 `load_full_result() or db_service.get_latest_analysis()`로 stats와 동일하게 DB 폴백하도록 함(파일별/유형별 차트는 `get_vulnerabilities` 재사용으로 함께 해결).
- 수정 파일: `api/server.py`

### 5. Defense 탭 레이아웃 정리 (설명문 가독성 + 전체 파일 diff)

- 문제: 블루팀 수정안 설명이 마크다운(`**굵게**`, 번호/글머리 목록, `---`)과 줄바꿈을 포함하는데 한 덩어리 문자열로 출력돼 읽기 어려웠음. 또한 Defense의 diff는 `original_code`(스니펫) vs `fixed_code`(파일 전체)라 거의 다 "+추가"로 보여 redscan과 모양이 달랐음.
- 수정(설명): 의존성 없는 경량 마크다운 렌더러 `Markdown` 컴포넌트를 추가해 줄바꿈 보존 + 굵게/인라인 코드/번호·글머리 목록(들여쓰기)/구분선을 사람이 보기 좋게 렌더함.
- 수정(diff): 분석 대상 **전체 원본 소스를 DB에 저장**(AES-256 암호화)하고, Defense 탭이 `buildFixedFile`로 redscan과 동일한 전체 파일 좌우 diff를 합성하도록 함. `/api/patches`가 패치마다 `source_full`을 함께 반환함.
- DB: `analysis_runs.source_code` 컬럼 추가 + 기존 SQLite DB에 컬럼이 없으면 자동으로 추가하는 마이그레이션(`_migrate_add_columns`)을 `init_db`에 넣음.
- 주의: 전체 원본은 이 변경 이후 실행한 스캔부터 저장됨. 이전 패치는 `source_full`이 없어 스니펫 단위 diff로 폴백함(전체 파일로 보려면 재스캔 필요).
- 수정 파일: `dashboard/src/components/Markdown.jsx`(신규), `dashboard/src/components/PatchView.jsx`, `api/server.py`, `db/models.py`, `db/service.py`, `analyzer/pipeline.py`

### 검증 (2차)

- `dashboard` `npm run build` 통과
- 브라우저 실측: 스캔→결과 렌더 정상(검은 화면 없음, 콘솔 에러 0), redscan/Defense diff 모두 전체 파일 split 렌더, Findings/Defense 탭 데이터 정상 표시
- API 일관성: `/api/stats`·`/api/vulnerabilities`·`/api/patches` 건수 일치, `/api/patches`에 `source_full` 포함
- diff 알고리즘: prefix/suffix 트리밍 결과가 기존 전체 LCS와 모든 케이스에서 동일함을 단위 검증

## 2026-06-01

### 1. 코드 비교 UI 개선 (GitHub PR diff 스타일)

- 문제: 수정 전/후 코드가 별도 코드 블록으로 위아래 나열되어, 어떤 라인이 바뀌었는지 한눈에 비교하기 어려웠음.
- 수정: 외부 라이브러리 없이 LCS 기반 라인 diff 알고리즘(`dashboard/src/utils/diff.js`)과 재사용 컴포넌트 `DiffView`를 추가함. 원본|수정본을 GitHub PR처럼 좌우 분할(기본)로 보여주고 변경 라인을 색으로 강조함(추가=녹색 `+`, 삭제=빨강 `-`). `split`/`unified` 토글과 `+N/-N` 통계를 제공함.
- 수정: 블루팀 수정(`PatchView`)과 레드스캔 결과(`AnalyzeView`)의 기존 분리형 코드 블록을 `DiffView`로 교체함.
- 수정: 두 화면 상단에 `$ jump →` 인덱스를 추가해, 취약점/패치 항목을 클릭하면 해당 코드·diff 영역으로 부드럽게 스크롤 이동(`scrollIntoView`)하도록 연결함.
- 수정 파일: `dashboard/src/utils/diff.js`(신규), `dashboard/src/components/DiffView.jsx`(신규), `dashboard/src/components/PatchView.jsx`, `dashboard/src/components/AnalyzeView.jsx`

### 2. 외부 라이브러리 처리 (서비스 코드 / 외부 라이브러리 분리)

- 문제: `node_modules`, minified JS, jquery/bootstrap 같은 외부 라이브러리 파일의 취약점이 실제 서비스 코드 결과에 섞여 노이즈가 컸음.
- 수정: 파일 분류 모듈(`shared/file_classifier.py`)을 추가함. vendor 디렉토리(`node_modules`/`vendor`/`dist` 등), 알려진 라이브러리 파일명(jquery/bootstrap/react 등), `*.min.js` 번들, minified 내용(긴 라인) 휴리스틱으로 `service`/`external`을 판별함.
- 수정: `quick-scan-project` API가 파일별 `category`/`is_external`/`external_reason`를 태깅하고, 서비스/외부 취약점 수를 분리 집계하도록 함.
- 수정: 프로젝트 뷰에 `서비스 코드만`(기본) / `외부 라이브러리` / `전체` 필터를 추가함. 파일 트리에 `EXT` 배지, 숨겨진 외부 취약점 건수 안내를 표시하고, 자동 선택도 서비스 파일을 우선하도록 보정함.
- 수정 파일: `shared/file_classifier.py`(신규), `api/server.py`, `dashboard/src/components/AnalyzeView.jsx`

### 3. 보안 기준 강화 (CWE + CVE + CVSS)

- 문제: 기존 분석이 CWE 중심이라 취약점별 CVE/CVSS/수정 우선순위 정보가 부족했음.
- 수정: CWE별 대표(참고) CVE 매핑(`shared/cwe_cve_map.json`)을 추가하고, 위험도 산정(`analyzer/risk_scorer.py`)에 `cve_ids`와 수정 우선순위 `fix_priority`(P1/P2/P3, CVSS+공격가능성+신뢰도 기반) 산정을 추가함(디스크 로드 캐싱 포함).
- 수정: 공통 데이터 계약(`shared/schemas.py`)에 `cve_ids`/`fix_priority`/`priority_label` 필드를 추가하고, Red/Blue 보강 로직(`shared/red_blue.py`)이 모든 읽기 경로에서 일관되게 채우도록 함.
- 수정: 취약점마다 CWE · CVE · CVSS · 위험등급 · 공격 가능성 · 수정 우선순위를 한 패널로 보여주는 `VulnMeta` 컴포넌트를 추가함(CWE→MITRE, CVE→NVD 링크). 취약점 테이블에 `CVSS`/`PRI`/`CVE` 컬럼을 추가함. 빠른 스캔(라이브/프로젝트) 결과에도 동일 정보를 부여함.
- 참고: 소스코드 취약점의 CVE는 동일 약점 클래스의 대표 예시라 UI에 "(참고)"로 명시하며, 의존성 스캔(pip-audit/npm)의 실제 CVE와 구분함.
- 수정 파일: `shared/cwe_cve_map.json`(신규), `analyzer/risk_scorer.py`, `shared/schemas.py`, `shared/red_blue.py`, `api/server.py`, `dashboard/src/components/VulnMeta.jsx`(신규), `dashboard/src/components/VulnTable.jsx`, `dashboard/src/components/AnalyzeView.jsx`

### 검증

- `py -m pytest tests/` 전체 106개 통과
- `dashboard` `npm run build` 통과 (664 modules)
- 백엔드 동작 확인: quick-scan 필드 부여, 프로젝트 파일 service/external 분류, CVE·수정 우선순위 산정 정상

## 2026-05-25

### 빠른 LLM patch 데모 옵션 및 진행 상태 개선

- 문제: LLM patch 생성 후 보안 재검증까지 항상 이어지면 데모 중 응답 시간이 길어지고, 사용자는 LLM 호출/재검증 중 어디에서 시간이 걸리는지 알기 어려웠음.
- 수정: `security_revalidation` 옵션을 API 요청과 대시보드 UI 토글로 분리함.
- 효과: 빠른 데모 모드에서는 LLM patch만 생성하고 보안 재검증은 나중에 실행할 수 있음. 대시보드 기본값은 빠른 데모에 맞춰 재검증 OFF로 설정함.
- 수정: LLM 실패 재시도 횟수를 `llm_max_retries`로 옵션화하고, 대시보드에서 0~3회로 조절할 수 있게 함. 기본값은 1회로 줄임.
- 유지: `batch_llm`은 기본 ON 상태를 유지해 같은 파일 취약점 여러 개를 한 번에 요청하도록 함.
- 수정: Gateway, Gemini, OpenRouter, OpenAI, Anthropic provider의 출력 토큰 기본값을 2048에서 4096으로 상향함. `LLM_MAX_OUTPUT_TOKENS` 환경변수로 조정 가능함.
- 수정: 진행 상태에 `LLM 호출 중... (1/2 · B608)`, `AI 배치 수정안 생성 중...`, `보안 재검증 중... (n건)`, `보안 재검증 스킵됨 (빠른 데모 모드)`처럼 실제 병목 단계를 표시하도록 개선함.
- 수정 파일: `dashboard/src/components/AnalyzeView.jsx`, `api/server.py`, `api/tasks.py`, `analyzer/pipeline.py`, `agent/llm_agent.py`, `agent/providers/*.py`
- 검증: Python 주요 파일 `py_compile` 통과, 관련 pytest 8개 통과, `dashboard` `npm run build` 통과, 브라우저에서 `security_revalidation`/`batch_llm` 토글 렌더링 확인.

## 2026-05-20

### OPS Blue Team verified/risk reduction 집계 보정

- 문제: LLM 패치가 `status=verified`이고 보안 재검증을 통과해도 `defense_outcome` 기본값이 빈 문자열이면 OPS Blue Team verified 집계가 0으로 표시될 수 있었음.
- 원인: `shared.red_blue.enrich_patch()`가 `setdefault()`를 사용해 빈 문자열 필드를 보정하지 못했음.
- 수정: Blue Team 필드가 비어 있으면 `validated_defense`/`drafted_defense`/`needs_review`를 명시적으로 채우도록 변경함.
- 수정: 보안 재검증이 통과했지만 도구 비교상 `removed_count=0`인 경우에도 검증된 패치 1건으로 risk reduction에 반영하도록 보정함.
- 테스트: verified patch가 Blue Team defense 및 risk reduction에 반영되는 회귀 테스트 추가.
- 수정 파일: `shared/red_blue.py`, `tests/test_pipeline_integration.py`

### LLM clean audit finding의 Blue Team 패치 생성 연결

- 문제: `ai_audit_clean`에서 LLM이 정적 분석이 놓친 취약점을 찾아도, 해당 finding이 Red Team 항목으로만 표시되고 Blue Team action과 risk reduction은 0으로 남았음.
- 원인: LLM clean audit 결과를 `VulnerabilityReport`로 승격한 뒤 다시 LLM 패치 생성 대상으로 넘기는 단계가 없었음.
- 수정: audit finding을 정식 취약점으로 승격한 직후 Blue Team 수정안 생성 단계로 연결함.
- 수정: audit finding에는 원본 코드 문맥을 `function_code`로 포함하고, LLM 최적화 단계에서 문맥 길이를 제한하도록 함.
- 수정 파일: `analyzer/pipeline.py`

### LLM 보안 수정 프롬프트 강화

- 문제: 기존 LLM 수정 프롬프트가 수정 코드와 근거 중심이라 Red Team 공격 분석, 프롬프트 인젝션 방어, 검증 체크리스트가 명확하지 않았음.
- 수정: 단일 수정안 프롬프트에 Red Team 분석, 수정 원칙, 프롬프트 인젝션 방어 문구, 검증 체크리스트를 추가함.
- 수정: 다중 수정안 프롬프트에도 동일한 보안 원칙과 잔여 위험 설명을 추가함.
- 호환성: 기존 응답 파서가 사용하는 `### 수정된 코드`, `### 수정 근거` heading은 유지함.
- 수정 파일: `agent/llm_agent.py`

### 사용자 LLM 프롬프트 입력 기능 추가

- 문제: 사용자가 분석 목적이나 수정 스타일을 직접 지정할 수 있는 입력창이 없었음.
- 수정: 대시보드 `llm_patch` 옵션 영역에 custom LLM instruction 입력창을 추가함.
- 백엔드: `AnalyzeRequest.user_prompt`를 추가하고 API 서버, Celery task, pipeline, `DalloAgent`까지 전달하도록 연결함.
- LLM 반영 범위: 단일 수정안, 다중 수정안, batch 수정안, clean audit 프롬프트에 사용자 지시가 반영됨.
- 보호 로직: 보안을 약화하거나 취약 코드를 유지하라는 지시는 무시하도록 프롬프트에 제한 문구를 추가함.
- 수정 파일: `dashboard/src/components/AnalyzeView.jsx`, `api/server.py`, `api/tasks.py`, `analyzer/pipeline.py`, `agent/llm_agent.py`

### README 현행화

- Red Team / Blue Team 기반 AI 공격·방어 분석 시스템 방향을 README에 유지하고, 현재 구현된 `user_prompt` 기능을 LLM 속도 최적화 섹션에 추가함.
- Gemini 중심 환경변수 설명을 API Gateway/Claude 기본 흐름으로 수정함.
- 정확도 측정 계획을 README에 추가함.
- 사용자 코드 입력부터 Red Team scan, LLM 기본 보안 프롬프트, 사용자 custom instruction 병합, Blue Team 수정안 검증까지의 프롬프트 반영 흐름을 README에 추가함.

### 검증

- Python 주요 파일 `py_compile` 통과
- 관련 pytest 7개 통과
- `dashboard` `npm run build` 통과
