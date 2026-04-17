"""
Anthropic(Claude) 프로바이더 (비활성 상태 — 향후 확장 대비 보존)

현재 메인 프로바이더는 Gemini입니다.
이 모듈은 추후 멀티 프로바이더 전략 재도입 시 사용합니다.

LLMProvider Protocol 준수.
"""

import os
import logging
from typing import Optional

from agent.providers.base import SYSTEM_PROMPT

logger = logging.getLogger(__name__)


class AnthropicProvider:
    """Anthropic Claude API 프로바이더 (비활성)"""

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-20250514", temperature: float = 0.2):
        self.model = model
        self.temperature = temperature
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._client = None

    def _ensure_client(self):
        if self._client is None:
            from anthropic import Anthropic
            self._client = Anthropic(api_key=self.api_key)

    def call(self, prompt: str, system: str = "") -> str:
        """LLM 호출 후 텍스트 응답 반환"""
        self._ensure_client()
        response = self._client.messages.create(
            model=self.model,
            max_tokens=2048,
            temperature=self.temperature,
            system=system or SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text

    def rotate_key(self) -> bool:
        """키 로테이션 미지원 (단일 키)"""
        return False
