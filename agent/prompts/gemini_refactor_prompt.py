"""
Gemini 전용 리팩토링 프롬프트 템플릿 (agent/prompts/gemini_refactor_prompt.py)

Gemini 모델 특성에 맞게 최적화된 프롬프트:
- 구조화된 JSON 응답 유도
- 한국어/영어 혼용 지원
- temperature 0.2 권장 (코드 생성 안정성)
"""


def build_single_patch_prompt(vuln_info: dict) -> str:
    """단일 취약점 수정 프롬프트 생성

    Args:
        vuln_info: {lang, rule_id, title, severity, description, cwe_id,
                    file_path, line_number, imports, code}
    """
    return f"""당신은 보안 코드 리뷰 전문가입니다. 아래 {vuln_info['lang']} 코드의 보안 취약점을 분석하고 수정된 코드를 제공하세요.

## 취약점 정보
- 언어: {vuln_info['lang']}
- 규칙: {vuln_info['rule_id']} ({vuln_info['title']})
- 심각도: {vuln_info['severity']}
- 설명: {vuln_info['description']}
- CWE: {vuln_info.get('cwe_id') or 'N/A'}
- 파일: {vuln_info['file_path']}:{vuln_info['line_number']}

## Import 문
```
{vuln_info.get('imports', '(없음)')}
```

## 취약한 코드
```
{vuln_info['code']}
```

## 요청사항
1. 위 취약점을 수정한 안전한 {vuln_info['lang']} 코드를 작성하세요.
2. 기존 기능(비즈니스 로직)은 유지하면서 보안만 강화하세요.
3. 수정 근거를 간단히 설명하세요.
4. 수정 코드는 바로 적용 가능해야 합니다.

## 응답 형식 (반드시 아래 형식을 지켜주세요)
### 수정된 코드
```
(여기에 수정된 전체 함수 코드를 작성하세요. 줄번호 없이 순수 {vuln_info['lang']} 코드만 작성하세요.)
```

### 수정 근거
(여기에 수정 이유를 설명하세요)
"""


def build_batch_patch_prompt(vulns: list[dict], lang: str) -> str:
    """같은 파일 내 여러 취약점을 한 번에 처리하는 배치 프롬프트

    Args:
        vulns: [{id, rule_id, title, severity, description, code, line_number}, ...]
        lang: 프로그래밍 언어
    """
    vuln_sections = []
    for i, v in enumerate(vulns, 1):
        vuln_sections.append(f"""### 취약점 {i}
- ID: {v['id']}
- 규칙: {v['rule_id']} ({v['title']})
- 심각도: {v['severity']}
- 설명: {v['description']}
- 위치: 라인 {v['line_number']}
```
{v['code']}
```""")

    vulns_text = "\n\n".join(vuln_sections)

    return f"""당신은 보안 코드 리뷰 전문가입니다. 아래 {lang} 파일에서 발견된 {len(vulns)}개 취약점을 각각 수정하세요.

{vulns_text}

## 응답 형식
반드시 아래 JSON 형식으로 응답하세요:
```json
{{
  "patches": [
    {{
      "vuln_id": "취약점 ID",
      "fixed_code": "수정된 전체 함수 코드",
      "explanation": "수정 근거"
    }}
  ]
}}
```

각 취약점별로 하나의 patch를 생성하세요. 코드에 줄번호를 포함하지 마세요.
"""
