"""
LLM 프로바이더 프로토콜 (agent/providers/base.py)

모든 LLM 프로바이더가 준수해야 하는 인터페이스를 정의합니다.
"""

from typing import Protocol, runtime_checkable

SYSTEM_PROMPT = (
    "당신은 보안 코드 리뷰 전문가입니다. "
    "다양한 프로그래밍 언어의 보안 취약점을 분석하고 수정된 코드를 제공합니다."
)


@runtime_checkable
class LLMProvider(Protocol):
    """LLM 프로바이더가 구현해야 하는 프로토콜"""

    model: str
    temperature: float

    def call(self, prompt: str, system: str = "") -> str:
        """프롬프트를 LLM에 전달하고 텍스트 응답을 반환합니다.

        Args:
            prompt: 사용자 프롬프트
            system: 시스템 프롬프트 (기본값 사용 시 빈 문자열)

        Returns:
            LLM 텍스트 응답
        """
        ...

    def rotate_key(self) -> bool:
        """다음 API 키로 전환합니다. 키가 1개뿐이면 False 반환."""
        ...
