"""
OpenAI 프로바이더 (비활성 상태 — 향후 확장 대비 보존)

현재 메인 프로바이더는 Gemini입니다.
이 모듈은 추후 멀티 프로바이더 전략 재도입 시 사용합니다.

LLMProvider Protocol 준수.
"""

import os
import logging
from typing import Optional

from agent.providers.base import SYSTEM_PROMPT

logger = logging.getLogger(__name__)


class OpenAIProvider:
    """OpenAI API 프로바이더 (비활성)"""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o", temperature: float = 0.2):
        self.model = model
        self.temperature = temperature
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self._client = None

    def _ensure_client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(api_key=self.api_key)

    def call(self, prompt: str, system: str = "") -> str:
        """LLM 호출 후 텍스트 응답 반환"""
        self._ensure_client()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=2048,
        )
        return response.choices[0].message.content

    def rotate_key(self) -> bool:
        """키 로테이션 미지원 (단일 키)"""
        return False
