# Dallo DevSecOps 변경 내역

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
