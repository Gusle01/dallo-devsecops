"""
API 인증 모듈 (api/auth.py)

X-API-Key 헤더 기반 API Key 인증.
환경변수 DALLO_API_KEYS에서 유효 키 목록을 로드합니다 (콤마 구분).

사용법:
    from api.auth import verify_api_key
    @app.get("/api/data", dependencies=[Depends(verify_api_key)])
    def get_data(): ...
"""

import os
import hmac
import logging
from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader

logger = logging.getLogger(__name__)

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _load_valid_keys() -> set[str]:
    """환경변수에서 유효 API 키 목록을 로드합니다."""
    raw = os.environ.get("DALLO_API_KEYS", "")
    if not raw:
        return set()
    return {k.strip() for k in raw.split(",") if k.strip()}


def _constant_time_compare(a: str, b: str) -> bool:
    """타이밍 공격 방지를 위한 상수 시간 문자열 비교"""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


async def verify_api_key(api_key: str = Security(_api_key_header)) -> str:
    """
    API Key를 검증합니다. 실패 시 401을 반환합니다.

    Returns:
        검증된 API Key (다운스트림에서 감사 로깅 등에 활용 가능)

    Raises:
        HTTPException(401): 키 누락 또는 무효
    """
    valid_keys = _load_valid_keys()

    # API 키가 아예 설정 안 된 경우 — 개발 환경 허용 (경고 출력)
    if not valid_keys:
        logger.warning(
            "[AUTH] DALLO_API_KEYS 미설정 — 인증을 건너뜁니다. "
            "운영 환경에서는 반드시 설정하세요."
        )
        return "no-auth-configured"

    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="API Key가 필요합니다. X-API-Key 헤더를 설정하세요.",
        )

    # 상수 시간 비교로 유효 키 확인 (타이밍 공격 방지)
    if not any(_constant_time_compare(api_key, valid) for valid in valid_keys):
        logger.warning("[AUTH] 유효하지 않은 API Key 시도")
        raise HTTPException(
            status_code=401,
            detail="유효하지 않은 API Key입니다.",
        )

    return api_key
