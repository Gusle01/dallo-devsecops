"""
LLM 프로바이더 팩토리 (agent/provider_factory.py)

환경변수 LLM_PRIMARY_PROVIDER에 따라 적절한 프로바이더를 반환합니다.
현재 활성 프로바이더: gemini, openrouter.
"""

import os
import logging
from typing import Optional

from agent.providers.base import LLMProvider

logger = logging.getLogger(__name__)

# 활성 프로바이더 (실제 호출 경로가 연결된 것)
_ACTIVE_PROVIDERS = {"gemini", "openrouter"}

# 등록된 프로바이더 (비활성 포함)
_REGISTERED_PROVIDERS = {"gemini", "openrouter", "openai", "anthropic"}

PRIMARY_PROVIDER = os.environ.get("LLM_PRIMARY_PROVIDER", "gemini").lower()


def get_provider(
    name: Optional[str] = None,
    api_key: Optional[str] = None,
    api_keys: Optional[list[str]] = None,
    model: Optional[str] = None,
    temperature: float = 0.2,
) -> LLMProvider:
    """
    프로바이더 인스턴스를 생성합니다.

    Args:
        name: 프로바이더 이름 (None이면 PRIMARY_PROVIDER 사용)
        api_key: API 키 (단일)
        api_keys: API 키 목록 (로테이션)
        model: 모델명 (None이면 프로바이더 기본값)
        temperature: 생성 온도

    Returns:
        LLMProvider 프로토콜을 만족하는 프로바이더 인스턴스

    Raises:
        ValueError: 알 수 없는 프로바이더 / 비활성 프로바이더
    """
    provider_name = (name or PRIMARY_PROVIDER).lower()

    if provider_name not in _REGISTERED_PROVIDERS:
        raise ValueError(
            f"알 수 없는 프로바이더: {provider_name}. "
            f"지원: {', '.join(sorted(_REGISTERED_PROVIDERS))}"
        )

    if provider_name not in _ACTIVE_PROVIDERS:
        raise ValueError(
            f"프로바이더 '{provider_name}'은 현재 비활성 상태입니다. "
            f"현재 활성: {', '.join(sorted(_ACTIVE_PROVIDERS))}. "
            f"LLM_PRIMARY_PROVIDER 환경변수를 확인하세요."
        )

    if provider_name == "gemini":
        from agent.providers.gemini_provider import GeminiProvider
        kwargs = {"temperature": temperature}
        if api_key:
            kwargs["api_key"] = api_key
        if api_keys:
            kwargs["api_keys"] = api_keys
        if model:
            kwargs["model"] = model
        return GeminiProvider(**kwargs)

    if provider_name == "openrouter":
        from agent.providers.openrouter_provider import OpenRouterProvider
        kwargs = {"temperature": temperature}
        if api_key:
            kwargs["api_key"] = api_key
        if api_keys:
            kwargs["api_keys"] = api_keys
        if model:
            kwargs["model"] = model
        return OpenRouterProvider(**kwargs)

    # 향후 활성화 시:
    # if provider_name == "openai":
    #     from agent.providers.openai_provider import OpenAIProvider
    #     return OpenAIProvider(api_key=api_key, model=model or "gpt-4o", temperature=temperature)
    # if provider_name == "anthropic":
    #     from agent.providers.anthropic_provider import AnthropicProvider
    #     return AnthropicProvider(api_key=api_key, model=model or "claude-sonnet-4-20250514", temperature=temperature)

    raise ValueError(f"프로바이더 '{provider_name}' 초기화 실패")
