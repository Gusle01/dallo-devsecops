# Dallo DevSecOps 변경 내역

## 2026-06-03 (6차 — 대시보드/공격·방어 위험도 갯수 불일치 수정)

### 1. 화면마다 위험도 갯수가 다르게 나오는 문제 수정 (CVSS 기준으로 통일)

- 문제: 같은 분석인데 대시보드 카드(예: HIGH 1)와 공격/방어 '심각·높음'(예: 2)의 위험도 갯수가 어긋남.
- 원인: 두 화면이 서로 다른 기준으로 카운트 — 대시보드 카드/파일별 차트는 도구 `severity`(HIGH/MEDIUM/LOW), 공격/방어 'critical_or_high'와 취약점 표의 CVSS 컬럼은 `risk_level`(CVSS 기반 critical/high/medium/low). 도구 severity와 CVSS가 달라질 수 있어(예: SSRF=MEDIUM이지만 CVSS 9.1=critical, 하드코딩 시크릿=HIGH지만 CVSS 9.1=critical) 숫자가 어긋남.
- 수정: 표시 위험도를 **CVSS `risk_level` 기준으로 통일**(critical은 '높음'에 합산):
  - `api/server.py` `_with_red_blue`: enrich된 취약점(risk_level 포함)으로 대시보드 summary의 high/medium/low를 재계산 → 대시보드 카드 == 공격/방어 '심각·높음'.
  - `api/server.py` `/api/vulnerabilities/by-file`: 파일별 차트(FileChart)도 risk_level 기준.
  - `dashboard/src/components/VulnTable.jsx`: 취약점 표의 심각도 배지·필터도 risk_level 기준(이제 CVSS 9.x는 CRITICAL 배지로 표시되어 CVSS 컬럼과 일치).
- 수정 파일: `api/server.py`, `dashboard/src/components/VulnTable.jsx`

### 검증 (6차)

- 실제 데이터 확인: `/api/stats`의 high == `/api/red-blue/summary` red_team.critical_or_high (1==1, 2==2 등), `/api/vulnerabilities/by-file`도 카드와 동일.
- `py_compile`(`api/server.py`) 통과, `dashboard` `npm run build` 통과(dist 재빌드).
- 참고: 이력(추이) 차트는 세션 저장 시점의 도구 severity 기반 저장값을 사용하므로 기존 세션은 옛 기준이 남을 수 있음(다음 분석부터 통일).

## 2026-06-03 (5차 — 레드팀 분석 실행 시 500/"request error" 수정 · 발표용 보고서 추가)

### 1. 분석 요청이 `[FAIL] request error: The string did not match the expected pattern`로 실패하는 문제 수정

- 문제: `레드팀 분석`에서 스캔 실행 시 `[FAIL] request error: The string did not match the expected pattern`가 표시되며 분석이 시작되지 않음.
- 원인: 백엔드 `POST /api/analyze`가 HTTP 500(text/plain "Internal Server Error")을 반환했고, 프론트가 그 비‑JSON 응답을 `resp.json()`으로 파싱하다 실패한 것(브라우저별 JSON 파싱 예외 메시지). 500의 근본 원인은 — 서버 시작 시 **한 번만** Redis 연결로 `_USE_CELERY`를 결정(`api/server.py:62~70`)하는데, 시작 당시 Redis가 떠 있어 Celery 모드로 고정된 뒤 **Redis가 꺼지면서** `run_analysis_task.delay()`가 런타임에 실패(처리 안 된 예외)했기 때문. Celery 경로에 브로커 장애 시 런타임 폴백이 없었음.
- 수정(백엔드, 근본): `POST /api/analyze`의 Celery 제출을 `try/except`로 감싸 **실패 시 메모리 방식으로 자동 폴백**(README의 "Redis 미실행 → 메모리 폴백"과 일치). GET 폴링 핸들러가 메모리 작업을 먼저 조회하므로 폴링도 그대로 동작.
- 수정(프론트, 방어): 응답이 `resp.ok`가 아니면 cryptic 파싱 오류 대신 `서버 오류 500 — …`처럼 원인이 보이는 메시지를 표시.
- 수정 파일: `api/server.py`, `dashboard/src/components/AnalyzeView.jsx`

### 2. 발표용 종합 보고서 추가

- `report.md` 추가 — 프로젝트 구성/동작 원리/기능별 상세/데이터 모델/화면/기술 스택/보안 설계/CI/CD를 한 곳에 정리한 발표 자료용 문서(README + 코드 레벨 사실 종합).

### 검증 (5차)

- `POST /api/analyze` → HTTP 200(`backend: memory`), 폴링 `analyzing → completed`, 취약점 2건 탐지 확인.
- `py_compile`(`api/server.py`) 통과, `dashboard` `npm run build` 통과(dist 재빌드).
- 참고: 무거운 분석을 별도 워커에서 안정적으로 처리하려면 Redis + Celery worker 실행 권장(현재는 Redis 없이도 메모리로 동작).

## 2026-06-02 (4차 패치 — 대시보드 라이트 테마 전환 · 한글화 · 리포트 최신화 · git push 수정)

### 1. 대시보드를 다크 터미널 → 라이트 테마로 전환 + 한글화

- 요구: 화면 전체 분위기를 밝게, "사람이 만든" 느낌으로. 기존 화면 구성은 최대한 유지.
- 수정(테마): 색 토큰을 단일 소스(`index.css` `:root`, `colors.js`)에서 라이트 팔레트로 재정의 → `var(--…)`/`COLORS.*`를 쓰는 대부분 컴포넌트가 자동 전환. 웜 오프화이트 배경, 흰 카드, 부드러운 그림자, 약간의 둥근 모서리. 악센트는 기존 인광 그린 정체성을 이은 성숙한 에메랄드(`#0a7d56`).
- 수정(폰트): 본문/UI는 Pretendard(한글+라틴), 로고·큰 숫자는 Fraunces(세리프), 코드는 JetBrains Mono.
- 수정(장식 완화): 스캔라인·비네팅·네온 글로우·깜빡이는 커서, `$`/`[ ]`/`:wq`/`# ` 등 과한 터미널 장식 제거.
- 수정(한글화): 메뉴 탭(레드팀 분석/공격·방어/대시보드/취약점/블루팀 수정/의존성/리포트/이력), 기능 토글(실시간 스캔·LLM 패치·다중 패치·일괄 처리·AI 정밀점검·보안 재검증), 페이지 제목·표 헤더·상태·푸터 등 사용자 노출 라벨을 한글화. 하드코딩된 다크 색(코드 에디터 `#15130f` 등)도 라이트로 교체.
- 수정 파일: `dashboard/src/index.css`, `dashboard/src/colors.js`, `dashboard/src/App.jsx`, `dashboard/src/components/*`(AnalyzeView, VulnTable, PatchView, RedBlueView, ReportView, DependencyView, LoginView, StatsCards, FileChart, TypeChart, DiffView 등)

### 2. 이력(로그) 탭 그래프 2개 → 1개로 통합

- 요구: 막대·선 두 차트를 하나로 합치고, X축/막대/점이 무엇인지 알려주기.
- 수정: recharts `ComposedChart`로 통합 — 막대(심각도별 탐지: 높음/중간/낮음, 왼쪽 Y축 "탐지 건수")와 선·점(패치 초안/검증, 오른쪽 Y축 "패치 수")을 한 차트에. X축 라벨 "세션 (오래된 → 최신)", 범례로 각 계열의 의미를 표기. 폰트·툴팁도 라이트 테마로.
- 수정 파일: `dashboard/src/components/HistoryView.jsx`

### 3. 리포트 라이트 테마 전환 + 구성 최신화 (diff · CVE)

- 요구: "리포트 생성 / open_report"로 열리는 PDF/HTML이 예전 다크 테마로 남아 있음. 지금 테마로 바꾸고 diff·CVE 등 최신화.
- 수정: 리포트 탭(클라이언트 생성 `ReportView`)과 레드팀 분석의 open_report(백엔드 생성 `report_generator.py`)를 모두 대시보드와 동일한 라이트 테마로 다시 작성. 탐지 표에 **CVSS·CWE·CVE 컬럼**(CWE→MITRE, CVE→NVD 링크, CVSS 점수 색상), 블루팀 수정마다 **수정 전/후 diff**(빨강 삭제·초록 추가, `+N −N`)와 보안 재검증 결과 추가. HTML/Markdown 모두 반영.
- 수정 파일: `dashboard/src/components/ReportView.jsx`, `reports/report_generator.py`

### 4. git push "브랜치 조회/생성 404" 수정

- 문제: apply-patch의 GitHub PR 생성에서 `MAIN 브랜치 조회 실패: 404` (이후 `브랜치 생성 실패: 404`).
- 원인: 입력칸은 `owner/repo` 형식인데 전체 URL(`https://github.com/owner/repo`)을 넣으면 `api.github.com/repos/https://github.com/...`로 호출되어 404. 또 기본 브랜치를 `main`으로 하드코딩해 다른 기본 브랜치(master 등)에서 실패. 브랜치 생성 단계의 404는 토큰 쓰기 권한 부족(공개 레포는 읽기만 됨)이 원인.
- 수정: 백엔드에 `_normalize_repo()`를 추가해 전체 URL/`.git`/슬래시를 `owner/repo`로 정규화(프론트도 전송 전 정규화). 레포 정보(`GET /repos/{repo}`)로 **기본 브랜치를 자동 감지**해 ref 조회·PR base에 사용. 404/401·쓰기 권한 부족에 GitHub 응답 본문 + 한글 안내(토큰 `repo`/Contents:write 권한 확인)를 표시.
- 수정 파일: `api/server.py`, `dashboard/src/components/AnalyzeView.jsx`

### 5. git push 자격 고정/저장 문제 수정

- 문제: 한 번 입력한 레포가 계속 고정되어 그 레포로만 push됨. 또 PAT를 브라우저 localStorage에 저장.
- 수정: `ApplyButton`이 repo/token을 localStorage에 저장·자동적용하던 로직을 제거하고, 매번 폼을 열어 확인·변경하도록 변경. 토큰은 더 이상 저장하지 않고 이번 요청에만 사용 후 폐기(보안 개선).
- 수정 파일: `dashboard/src/components/AnalyzeView.jsx`

### 검증 (4차)

- `dashboard` `npm run build` 통과(665 모듈). 헤드리스 Chrome로 로그인·8개 탭·이력 차트·리포트를 API 목킹 렌더해 라이트 테마/한글/diff/CVE 확인.
- Python `py_compile`(`api/server.py`, `reports/report_generator.py`) 통과. 리포트 생성기를 목 데이터로 렌더해 CVE·before/after diff·라이트 테마 확인.
- `_normalize_repo` 단위 확인: `https://github.com/Gusle01/WebGoat`(및 `.git`/`/tree/main`/공백 변형) → `Gusle01/WebGoat`.

## 2026-06-01 (3차 패치 — Defense diff 잘림 / Findings CVSS 표시 수정)

### 1. Defense 탭에서 diff가 잘려 보이는 문제 수정

- 문제: 블루팀 수정안을 펼쳤을 때, 설명이 길면 하단의 diff가 잘려서 일부만 보였음.
- 원인: 펼침 애니메이션 클래스 `.expand-in`이 종료 상태로 `max-height: 800px` + `overflow: hidden`을 유지함. 상세(설명+메타+diff) 높이가 800px를 넘으면 그 아래(주로 diff)가 클리핑됨. 설명이 짧을 때는 800px 안에 들어와 정상으로 보여 재현이 까다로웠음.
- 수정: `max-height`/`overflow:hidden` 클램프를 제거하고 페이드+슬라이드(`opacity`+`translateY`)로만 노출하도록 `@keyframes expandIn`과 `.expand-in`을 변경함 → 상세 내용이 어떤 높이든 전부 표시됨. Defense(`PatchView`)와 Findings 펼침 행(`VulnTable`)에 공통 적용.
- 보강: diff 셀에 `overflow-wrap: anywhere`를 추가해, 긴 토큰(연결 문자열/시크릿 등)이 Safari 등에서 가로로 넘쳐 잘리는 경우도 방지함.
- 수정 파일: `dashboard/src/index.css`, `dashboard/src/components/DiffView.jsx`

### 2. Findings 탭에서 CVSS 점수가 "--"로 표시되는 문제 수정

- 문제: 취약점 목록의 CVSS 컬럼이 "--"로 비어 보였음(CVE/우선순위는 정상 표시).
- 원인: `cvss_score`/`risk_level`은 파이프라인의 risk_scorer가 계산하지만 DB에 저장되지 않음(컬럼 없음). DB에서 로드된 취약점은 읽기 시점 보강(`enrich_vulnerability`)에서 cve_ids·fix_priority만 채우고 cvss/risk_level은 채우지 않아 비어 있었음.
- 수정: `shared/red_blue.py`의 `_enrich_cve_and_priority`가 cvss_score/risk_level이 비어 있으면 `score_risk()`(CWE→CVSS 매핑 + severity 폴백)로 재계산해 채우도록 함. 이로써 stats·findings·defense가 동일한 위험도 값을 일관되게 보여줌.
- 수정 파일: `shared/red_blue.py`

### 검증 (3차)

- `dashboard` `npm run build` 통과
- 브라우저 실측: Defense 상세 높이 1935px(기존 800px 클램프 초과)에서도 diff 잘림 없이 전부 표시, `.expand-in`이 `max-height:none`/`overflow:visible`, 콘솔 에러 0
- API: `/api/vulnerabilities`의 `HEUR-HARDCODED-SECRET`이 `cvss_score=9.1 / risk_level=critical / fix_priority=P1`로 정상 표시

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
