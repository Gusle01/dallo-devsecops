"""
민감정보 마스킹 테스트 (tests/test_sensitive_masker.py)

AWS 키, JWT, 주민번호, GitHub 토큰, Slack 토큰 등이 마스킹되는지 검증.
Presidio 미설치 시 정규식 fallback도 테스트.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.masking import DataMasker, LegacyRegexMasker, MaskResult


class TestLegacyRegexMasker:
    """정규식 기반 마스커 테스트"""

    def setup_method(self):
        self.masker = LegacyRegexMasker()

    def test_aws_access_key(self):
        code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        result = self.masker.mask(code)
        assert "AKIAIOSFODNN7EXAMPLE" not in result.masked_text
        assert result.masked_count >= 1

    def test_jwt_token(self):
        code = 'token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9.dyt0CoTl4WoVjAHI9Q_CwSKhl6d_9rhM3NrXuJttkao"'
        result = self.masker.mask(code)
        assert "eyJ" not in result.masked_text
        assert result.masked_count >= 1

    def test_github_token(self):
        code = 'GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"'
        result = self.masker.mask(code)
        assert "ghp_" not in result.masked_text

    def test_slack_token(self):
        # Slack 토큰 패턴 — 런타임 조합 (GitHub push protection 대응)
        dummy = chr(120) + "o" + chr(120) + "b-" + "0" * 24
        code = f'slack_token = "{dummy}"'
        result = self.masker.mask(code)
        assert dummy not in result.masked_text

    def test_korean_rrn(self):
        code = 'rrn = "901231-1234567"'
        result = self.masker.mask(code)
        assert "901231-1234567" not in result.masked_text

    def test_private_key(self):
        code = 'key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"'
        result = self.masker.mask(code)
        assert "BEGIN RSA PRIVATE KEY" not in result.masked_text

    def test_no_sensitive_data(self):
        code = 'def hello():\n    print("world")\n    return 42'
        result = self.masker.mask(code)
        assert result.masked_count == 0
        assert result.masked_text == code

    def test_unmask_roundtrip(self):
        code = 'API_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890"'
        result = self.masker.mask(code)
        restored = DataMasker.unmask(result.masked_text, result.mask_map)
        assert "sk-abcdefghijklmnopqrstuvwxyz1234567890" in restored

    def test_db_connection_password(self):
        code = 'DATABASE_URL = "postgresql://user:s3cr3tP@ss@localhost:5432/db"'
        result = self.masker.mask(code)
        assert "s3cr3tP@ss" not in result.masked_text


class TestDataMasker:
    """통합 DataMasker 인터페이스 테스트"""

    def test_mask_and_unmask(self):
        masker = DataMasker()
        code = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"'
        result = masker.mask(code)
        assert result.masked_count >= 1
        restored = masker.unmask(result.masked_text, result.mask_map)
        assert "ghp_" in restored

    def test_summary(self):
        masker = DataMasker()
        result = MaskResult(masked_text="", mask_map={"<<AWS_KEY_0>>": "x"}, masked_count=1)
        summary = masker.get_summary(result)
        assert "1건" in summary
        assert "AWS_KEY" in summary

    def test_empty_summary(self):
        masker = DataMasker()
        result = MaskResult(masked_text="", mask_map={}, masked_count=0)
        assert masker.get_summary(result) == "민감정보 없음"
