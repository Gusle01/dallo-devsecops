"""
API Gateway 프로바이더 (agent/providers/gateway_provider.py)

OpenAI Chat Completions 호환 Gateway를 통해 여러 LLM 모델을 호출합니다.
"""

import logging
import os
from typing import Optional

from agent.providers.base import SYSTEM_PROMPT

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://factchat-cloud.mindlogic.ai/v1/gateway"
DEFAULT_MODEL = "claude-sonnet-4-6"


class GatewayProvider:
    """OpenAI SDK 호환 API Gateway 프로바이더."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_keys: Optional[list[str]] = None,
        model: str = DEFAULT_MODEL,
        temperature: float = 0.2,
        base_url: Optional[str] = None,
    ):
        self.model = model
        self.temperature = temperature
        self.base_url = base_url or os.environ.get("GATEWAY_BASE_URL", DEFAULT_BASE_URL)

        if api_keys:
            self._api_keys = [k for k in api_keys if k.strip()]
        elif api_key:
            self._api_keys = [api_key]
        else:
            env_val = os.environ.get("GATEWAY_API_KEY", "")
            self._api_keys = [k.strip() for k in env_val.split(",") if k.strip()]

        if not self._api_keys:
            raise ValueError(
                "Gateway API 키가 필요합니다. GATEWAY_API_KEY 환경변수를 설정하세요."
            )

        self._current_key_idx = 0
        self._client = self._make_client(self._api_keys[0])

    def _make_client(self, api_key: str):
        from openai import OpenAI

        return OpenAI(
            base_url=self.base_url,
            api_key=api_key,
        )

    def rotate_key(self) -> bool:
        if len(self._api_keys) <= 1:
            return False
        self._current_key_idx = (self._current_key_idx + 1) % len(self._api_keys)
        self._client = self._make_client(self._api_keys[self._current_key_idx])
        logger.info(f"Gateway API 키 전환 → 키 #{self._current_key_idx + 1}")
        return True

    def call(self, prompt: str, system: str = "") -> str:
        response = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system or SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=self.temperature,
            max_tokens=2048,
        )
        return response.choices[0].message.content
