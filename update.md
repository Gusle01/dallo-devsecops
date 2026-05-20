# Dallo DevSecOps 변경 내역

## 2026-05-20

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
