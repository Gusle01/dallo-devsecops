"""Syntax Checker 테스트"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validator.syntax_checker import SyntaxChecker, CheckResult
from shared.schemas import PatchSuggestion, PatchStatus


class TestSyntaxChecker:
    """SyntaxChecker 클래스 테스트"""

    def setup_method(self):
        self.checker = SyntaxChecker()

    def test_valid_code(self):
        """문법적으로 올바른 코드"""
        patch = PatchSuggestion(
            vulnerability_id="test_001",
            fixed_code='def safe_query(user_id):\n    query = "SELECT * FROM users WHERE id = ?"\n    return query',
            explanation="test",
            status=PatchStatus.GENERATED,
        )
        result = self.checker.check(patch)
        assert result.syntax_valid is True
        assert result.status != PatchStatus.FAILED

    def test_invalid_code(self):
        """문법 오류가 있는 코드"""
        patch = PatchSuggestion(
            vulnerability_id="test_002",
            fixed_code='def broken(\n    print("missing paren"',
            explanation="test",
            status=PatchStatus.GENERATED,
        )
        result = self.checker.check(patch)
        assert result.syntax_valid is False
        assert result.status == PatchStatus.FAILED

    def test_empty_code(self):
        """빈 코드"""
        patch = PatchSuggestion(
            vulnerability_id="test_003",
            fixed_code="",
            explanation="test",
            status=PatchStatus.GENERATED,
        )
        result = self.checker.check(patch)
        assert result.syntax_valid is False
        assert result.status == PatchStatus.FAILED

    def test_complex_valid_code(self):
        """복잡한 유효 코드"""
        code = '''
import hashlib
import bcrypt

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())
'''
        patch = PatchSuggestion(
            vulnerability_id="test_004",
            fixed_code=code,
            explanation="test",
            status=PatchStatus.GENERATED,
        )
        result = self.checker.check(patch)
        assert result.syntax_valid is True

    def test_batch_check(self):
        """일괄 검증"""
        patches = [
            PatchSuggestion(vulnerability_id="a", fixed_code="x = 1", explanation="", status=PatchStatus.GENERATED),
            PatchSuggestion(vulnerability_id="b", fixed_code="x = (", explanation="", status=PatchStatus.GENERATED),
            PatchSuggestion(vulnerability_id="c", fixed_code="y = 2", explanation="", status=PatchStatus.GENERATED),
        ]
        results = self.checker.check_batch(patches)
        assert results[0].syntax_valid is True
        assert results[1].syntax_valid is False
        assert results[2].syntax_valid is True

    def test_check_syntax_internal(self):
        """내부 _check_syntax 메서드"""
        ok = self.checker._check_syntax("x = 1 + 2")
        assert ok.valid is True
        assert ok.error_message is None

        bad = self.checker._check_syntax("x = (")
        assert bad.valid is False
        assert bad.error_line is not None
