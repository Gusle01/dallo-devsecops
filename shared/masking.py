"""
민감정보 마스킹 모듈 (shared/masking.py)

코드를 LLM에 전송하기 전에 API 키, 비밀번호, 토큰 등
민감정보를 마스킹하고, LLM 응답을 받은 후 원래 값으로 복원합니다.

기본적으로 Presidio 엔진을 사용하며, 설치되지 않은 경우 정규식 기반 fallback.

사용법:
    from shared.masking import DataMasker

    masker = DataMasker()
    result = masker.mask(original_code)
    # result.masked_text를 LLM에 전송
    restored = masker.unmask(llm_response, result.mask_map)
"""

import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ============================================================
# 공통 데이터 구조
# ============================================================

@dataclass
class MaskResult:
    """마스킹 결과"""
    masked_text: str
    mask_map: dict = field(default_factory=dict)  # {MASKED_PLACEHOLDER: original_value}
    masked_count: int = 0


# ============================================================
# 정규식 기반 마스커 (Fallback)
# ============================================================

SENSITIVE_PATTERNS = [
    (r'(sk-[a-zA-Z0-9\-_]{20,})', "OPENAI_KEY"),
    (r'(sk-ant-[a-zA-Z0-9\-_]{20,})', "ANTHROPIC_KEY"),
    (r'(AIza[A-Za-z0-9\-_]{30,})', "GOOGLE_KEY"),
    (r'(ghp_[a-zA-Z0-9]{30,})', "GITHUB_TOKEN"),
    (r'(gho_[a-zA-Z0-9]{30,})', "GITHUB_OAUTH"),
    (r'(AKIA[A-Z0-9]{16})', "AWS_ACCESS_KEY"),
    (r'(xoxb-[0-9A-Za-z\-]{20,})', "SLACK_TOKEN"),
    (r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})', "JWT_TOKEN"),
    (r'(?:postgresql|mysql|mongodb)://[^:]+:([^@]+)@', "DB_CONN_PASSWORD"),
    (r'(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_KEY|DB_PASSWORD|JWT_SECRET|SECRET_KEY)\s*[=:]\s*["\']([^"\']{4,})["\']', "SECRET_VALUE"),
    (r'[Bb]earer\s+([A-Za-z0-9\-_.]{20,})', "BEARER_TOKEN"),
    (r'(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----.*?-----END (?:RSA |EC )?PRIVATE KEY-----)', "PRIVATE_KEY"),
    # 한국 주민등록번호 (YYMMDD-NNNNNNN)
    (r'(\d{6}[-]\d{7})', "KR_RRN"),
]


class LegacyRegexMasker:
    """정규식 기반 민감정보 마스킹 (Presidio 미설치 시 fallback)"""

    def __init__(self):
        self._counter = 0

    def mask(self, code: str) -> MaskResult:
        masked = code
        mask_map = {}
        self._counter = 0

        for pattern, label in SENSITIVE_PATTERNS:
            matches = list(re.finditer(pattern, masked, re.IGNORECASE | re.DOTALL))
            for match in reversed(matches):
                group_idx = 1 if match.lastindex and match.lastindex >= 1 else 0
                sensitive_part = match.group(group_idx)
                placeholder = f"<<{label}_{self._counter}>>"
                if "<<" in sensitive_part:
                    continue
                mask_map[placeholder] = sensitive_part
                start = match.start(group_idx)
                end = match.end(group_idx)
                masked = masked[:start] + placeholder + masked[end:]
                self._counter += 1

        return MaskResult(masked_text=masked, mask_map=mask_map, masked_count=len(mask_map))


# ============================================================
# Presidio 기반 마스커
# ============================================================

class PresidioMasker:
    """Microsoft Presidio 기반 민감정보 탐지 + 마스킹"""

    def __init__(self):
        self._analyzer = None
        self._anonymizer = None
        self._counter = 0
        self._initialized = False
        self._init_presidio()

    def _init_presidio(self):
        """Presidio 엔진을 초기화합니다."""
        try:
            from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
            from presidio_anonymizer import AnonymizerEngine

            self._analyzer = AnalyzerEngine()
            self._anonymizer = AnonymizerEngine()

            # 커스텀 recognizer 추가
            custom_recognizers = [
                PatternRecognizer(
                    supported_entity="JWT_TOKEN",
                    name="jwt_recognizer",
                    patterns=[Pattern(
                        name="jwt",
                        regex=r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                        score=0.9,
                    )],
                ),
                PatternRecognizer(
                    supported_entity="SLACK_TOKEN",
                    name="slack_recognizer",
                    patterns=[Pattern(
                        name="slack_bot",
                        regex=r"xoxb-[0-9A-Za-z\-]{20,}",
                        score=0.9,
                    )],
                ),
                PatternRecognizer(
                    supported_entity="GITHUB_TOKEN",
                    name="github_recognizer",
                    patterns=[Pattern(
                        name="github_pat",
                        regex=r"ghp_[a-zA-Z0-9]{30,}",
                        score=0.9,
                    ), Pattern(
                        name="github_oauth",
                        regex=r"gho_[a-zA-Z0-9]{30,}",
                        score=0.9,
                    )],
                ),
                PatternRecognizer(
                    supported_entity="AWS_KEY",
                    name="aws_recognizer",
                    patterns=[Pattern(
                        name="aws_access_key",
                        regex=r"AKIA[A-Z0-9]{16}",
                        score=0.95,
                    )],
                ),
                PatternRecognizer(
                    supported_entity="KR_RRN",
                    name="kr_rrn_recognizer",
                    patterns=[Pattern(
                        name="korean_rrn",
                        regex=r"\d{6}[-]\d{7}",
                        score=0.9,
                    )],
                    supported_language="en",
                ),
            ]

            for recognizer in custom_recognizers:
                self._analyzer.registry.add_recognizer(recognizer)

            self._initialized = True
            logger.info("[MASKING] Presidio 엔진 초기화 완료")

        except ImportError:
            logger.info("[MASKING] Presidio 미설치 — 정규식 fallback 사용")
            self._initialized = False

    def mask(self, code: str) -> MaskResult:
        """Presidio를 사용하여 민감정보를 마스킹합니다."""
        if not self._initialized:
            return LegacyRegexMasker().mask(code)

        mask_map = {}
        self._counter = 0

        # Presidio 분석
        results = self._analyzer.analyze(
            text=code,
            language="en",
            entities=[
                "CREDIT_CARD", "EMAIL_ADDRESS", "PHONE_NUMBER",
                "PERSON", "IP_ADDRESS",
                "JWT_TOKEN", "SLACK_TOKEN", "GITHUB_TOKEN",
                "AWS_KEY", "KR_RRN",
            ],
        )

        # 점수 순으로 정렬 (높은 것 먼저), 위치 역순으로 치환
        results.sort(key=lambda r: r.start, reverse=True)

        masked = code
        for result in results:
            if result.score < 0.5:
                continue
            original = code[result.start:result.end]
            label = result.entity_type
            placeholder = f"<<{label}_{self._counter}>>"
            mask_map[placeholder] = original
            masked = masked[:result.start] + placeholder + masked[result.end:]
            self._counter += 1

        # Presidio가 못 잡는 것은 정규식으로 보완
        regex_masker = LegacyRegexMasker()
        regex_result = regex_masker.mask(masked)

        # 정규식 결과 병합 (이미 마스킹된 것은 제외)
        final_map = {**mask_map, **regex_result.mask_map}

        return MaskResult(
            masked_text=regex_result.masked_text,
            mask_map=final_map,
            masked_count=len(final_map),
        )


# ============================================================
# 통합 인터페이스 — 기존 호환
# ============================================================

class DataMasker:
    """민감정보 마스킹/복원 처리기 (Presidio 우선, 정규식 fallback)"""

    def __init__(self):
        try:
            self._masker = PresidioMasker()
            if not self._masker._initialized:
                self._masker = LegacyRegexMasker()
        except ImportError:
            self._masker = LegacyRegexMasker()

    def mask(self, code: str) -> MaskResult:
        return self._masker.mask(code)

    @staticmethod
    def unmask(text: str, mask_map: dict) -> str:
        """마스킹된 텍스트를 원래 값으로 복원합니다."""
        result = text
        for placeholder, original in mask_map.items():
            result = result.replace(placeholder, original)
        return result

    @staticmethod
    def get_summary(mask_result: MaskResult) -> str:
        if mask_result.masked_count == 0:
            return "민감정보 없음"
        types = set()
        for key in mask_result.mask_map:
            label = key.strip("<>").rsplit("_", 1)[0]
            types.add(label)
        return f"{mask_result.masked_count}건 마스킹 ({', '.join(sorted(types))})"
