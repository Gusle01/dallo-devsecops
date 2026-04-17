"""
Gemini 프로바이더 (agent/providers/gemini_provider.py)

메인 프로바이더. 무료 API 키 로테이션을 지원합니다.
"""

import os
import logging
from typing import Optional

from agent.providers.base import SYSTEM_PROMPT

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gemini-2.0-flash-lite"


class GeminiProvider:
    """Google Gemini API 프로바이더"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_keys: Optional[list[str]] = None,
        model: str = DEFAULT_MODEL,
        temperature: float = 0.2,
    ):
        self.model = model
        self.temperature = temperature

        # 멀티 API 키 지원 (로테이션)
        if api_keys:
            self._api_keys = [k for k in api_keys if k.strip()]
        elif api_key:
            self._api_keys = [api_key]
        else:
            env_val = os.environ.get("GEMINI_API_KEY", "")
            self._api_keys = [k.strip() for k in env_val.split(",") if k.strip()]

        if not self._api_keys:
            raise ValueError(
                "Gemini API 키가 필요합니다. GEMINI_API_KEY 환경변수를 설정하거나 "
                "api_key/api_keys 파라미터를 전달하세요."
            )

        self._current_key_idx = 0
        self._client = self._make_client(self._api_keys[0])

        if len(self._api_keys) > 1:
            logger.info(f"Gemini API 키 {len(self._api_keys)}개 로드됨 (로테이션 활성화)")

    def _make_client(self, api_key: str):
        from google import genai
        return genai.Client(api_key=api_key)

    def rotate_key(self) -> bool:
        """다음 API 키로 전환합니다."""
        if len(self._api_keys) <= 1:
            return False
        self._current_key_idx = (self._current_key_idx + 1) % len(self._api_keys)
        self._client = self._make_client(self._api_keys[self._current_key_idx])
        logger.info(f"Gemini API 키 전환 → 키 #{self._current_key_idx + 1}")
        return True

    def call(self, prompt: str, system: str = "") -> str:
        """Gemini API를 호출하고 텍스트 응답을 반환합니다."""
        from google.genai import types

        # Gemini는 system prompt를 contents 앞에 prepend
        full_prompt = prompt
        if system:
            full_prompt = f"{system}\n\n{prompt}"

        response = self._client.models.generate_content(
            model=self.model,
            contents=full_prompt,
            config=types.GenerateContentConfig(
                temperature=self.temperature,
                max_output_tokens=2048,
            ),
        )
        return response.text
