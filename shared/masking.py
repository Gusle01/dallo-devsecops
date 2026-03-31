"""
민감정보 마스킹 모듈 (shared/masking.py)

코드를 LLM에 전송하기 전에 API 키, 비밀번호, 토큰 등
민감정보를 마스킹하고, LLM 응답을 받은 후 원래 값으로 복원합니다.

사용법:
    from shared.masking import DataMasker

    masker = DataMasker()
    masked_code, mask_map = masker.mask(original_code)
    # masked_code를 LLM에 전송
    # LLM 응답에서 복원
    restored_code = masker.unmask(llm_response, mask_map)
"""

import re
from dataclasses import dataclass, field


# 민감정보 패턴 정의
SENSITIVE_PATTERNS = [
    # 특정 서비스 키 (먼저 매칭 — 더 구체적인 패턴 우선)
    (r'(sk-[a-zA-Z0-9\-_]{20,})', "OPENAI_KEY"),
    (r'(sk-ant-[a-zA-Z0-9\-_]{20,})', "ANTHROPIC_KEY"),
    (r'(AIza[A-Za-z0-9\-_]{30,})', "GOOGLE_KEY"),
    (r'(ghp_[a-zA-Z0-9]{30,})', "GITHUB_TOKEN"),
    (r'(gho_[a-zA-Z0-9]{30,})', "GITHUB_OAUTH"),
    (r'(AKIA[A-Z0-9]{16})', "AWS_ACCESS_KEY"),

    # Connection strings (비밀번호 부분만)
    (r'(?:postgresql|mysql|mongodb)://[^:]+:([^@]+)@', "DB_CONN_PASSWORD"),

    # 변수 할당 형태 (password, secret, key 등)
    (r'(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_KEY|DB_PASSWORD|JWT_SECRET|SECRET_KEY)\s*[=:]\s*["\']([^"\']{4,})["\']', "SECRET_VALUE"),

    # Bearer 토큰
    (r'[Bb]earer\s+([A-Za-z0-9\-_.]{20,})', "BEARER_TOKEN"),

    # Private keys
    (r'(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----.*?-----END (?:RSA |EC )?PRIVATE KEY-----)', "PRIVATE_KEY"),
]


@dataclass
class MaskResult:
    """마스킹 결과"""
    masked_text: str
    mask_map: dict = field(default_factory=dict)  # {MASKED_PLACEHOLDER: original_value}
    masked_count: int = 0


class DataMasker:
    """민감정보 마스킹/복원 처리기"""

    def __init__(self):
        self._counter = 0

    def mask(self, code: str) -> MaskResult:
        """
        코드에서 민감정보를 찾아 마스킹합니다.

        Args:
            code: 원본 코드

        Returns:
            MaskResult: 마스킹된 코드 + 복원용 매핑
        """
        masked = code
        mask_map = {}
        self._counter = 0

        for pattern, label in SENSITIVE_PATTERNS:
            matches = list(re.finditer(pattern, masked, re.IGNORECASE | re.DOTALL))
            for match in reversed(matches):
                # 첫 번째 캡처 그룹의 값을 마스킹
                group_idx = 1 if match.lastindex and match.lastindex >= 1 else 0
                sensitive_part = match.group(group_idx)
                placeholder = f"<<{label}_{self._counter}>>"

                # 이미 마스킹된 부분은 스킵
                if "<<" in sensitive_part:
                    continue

                mask_map[placeholder] = sensitive_part
                start = match.start(group_idx)
                end = match.end(group_idx)
                masked = masked[:start] + placeholder + masked[end:]
                self._counter += 1

        return MaskResult(
            masked_text=masked,
            mask_map=mask_map,
            masked_count=len(mask_map),
        )

    def unmask(self, text: str, mask_map: dict) -> str:
        """
        마스킹된 텍스트를 원래 값으로 복원합니다.

        Args:
            text: 마스킹된 텍스트
            mask_map: mask()에서 반환된 매핑

        Returns:
            복원된 텍스트
        """
        result = text
        for placeholder, original in mask_map.items():
            result = result.replace(placeholder, original)
        return result

    def get_summary(self, mask_result: MaskResult) -> str:
        """마스킹 요약 정보를 반환합니다."""
        if mask_result.masked_count == 0:
            return "민감정보 없음"

        types = set()
        for key in mask_result.mask_map:
            # <<TYPE_0>> → TYPE
            label = key.strip("<>").rsplit("_", 1)[0]
            types.add(label)

        return f"{mask_result.masked_count}건 마스킹 ({', '.join(sorted(types))})"
