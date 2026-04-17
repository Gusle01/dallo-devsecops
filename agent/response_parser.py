"""
LLM 응답 파서 (agent/response_parser.py)

Gemini의 JSON 구조 응답을 파싱합니다.
{"patches": [{"vuln_id": ..., "fixed_code": ..., "explanation": ...}, ...]}
"""

import json
import re
import logging

logger = logging.getLogger(__name__)


def extract_json_from_response(text: str) -> dict:
    """LLM 응답에서 JSON 객체를 추출합니다.

    여러 전략을 시도합니다:
    1. ```json ... ``` 블록
    2. { ... } 최외곽 JSON
    3. 직접 파싱
    """
    # 전략 1: 코드 블록 내 JSON
    json_match = re.search(r"```(?:json)?\s*\n(.*?)```", text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # 전략 2: 최외곽 { ... }
    brace_match = re.search(r"\{[\s\S]*\}", text)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass

    # 전략 3: 전체 텍스트를 직접 파싱
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        pass

    logger.warning("[PARSER] JSON 파싱 실패")
    return {}


def extract_patches_from_json(data: dict) -> list[dict]:
    """JSON 구조에서 패치 리스트를 추출합니다."""
    if "patches" in data:
        return data["patches"]
    if isinstance(data, list):
        return data
    return []
