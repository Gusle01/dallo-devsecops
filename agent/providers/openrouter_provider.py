"""
OpenRouter 프로바이더 (agent/providers/openrouter_provider.py)

OpenRouter API를 통해 다양한 모델(Qwen, Llama 등)을 호출합니다.
OpenAI SDK 호환 API를 사용합니다.
"""

import os
import logging
from typing import Optional

from agent.providers.base import SYSTEM_PROMPT

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "qwen/qwen3-235b-a22b"


class OpenRouterProvider:
    """OpenRouter API 프로바이더"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_keys: Optional[list[str]] = None,
        model: str = DEFAULT_MODEL,
        temperature: float = 0.2,
    ):
        self.model = model
        self.temperature = temperature

        if api_keys:
            self._api_keys = [k for k in api_keys if k.strip()]
        elif api_key:
            self._api_keys = [api_key]
        else:
            env_val = os.environ.get("OPENROUTER_API_KEY", "")
            self._api_keys = [k.strip() for k in env_val.split(",") if k.strip()]

        if not self._api_keys:
            raise ValueError(
                "OpenRouter API 키가 필요합니다. OPENROUTER_API_KEY 환경변수를 설정하세요."
            )

        self._current_key_idx = 0
        self._client = self._make_client(self._api_keys[0])

    def _make_client(self, api_key: str):
        from openai import OpenAI
        return OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
        )

    def rotate_key(self) -> bool:
        if len(self._api_keys) <= 1:
            return False
        self._current_key_idx = (self._current_key_idx + 1) % len(self._api_keys)
        self._client = self._make_client(self._api_keys[self._current_key_idx])
        logger.info(f"OpenRouter API 키 전환 → 키 #{self._current_key_idx + 1}")
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
