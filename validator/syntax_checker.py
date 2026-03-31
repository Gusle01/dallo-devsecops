"""
문법 검증 모듈 (validator/syntax_checker.py)

LLM이 생성한 수정 코드가 문법적으로 올바른지 검증합니다.

사용법:
    from validator.syntax_checker import SyntaxChecker

    checker = SyntaxChecker()
    result = checker.check(patch)
    # result.syntax_valid = True/False
"""

import ast
import sys
import os
import tempfile
import subprocess
from dataclasses import dataclass
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.schemas import PatchSuggestion, PatchStatus


@dataclass
class CheckResult:
    """문법 검사 결과"""
    valid: bool
    error_message: Optional[str] = None
    error_line: Optional[int] = None


class SyntaxChecker:
    """LLM 생성 코드의 문법 검증기"""

    def check(self, patch: PatchSuggestion) -> PatchSuggestion:
        """
        PatchSuggestion의 fixed_code 문법을 검증하고 결과를 업데이트합니다.

        Args:
            patch: LLM이 생성한 수정안

        Returns:
            문법 검증 결과가 반영된 PatchSuggestion
        """
        if not patch.fixed_code or not patch.fixed_code.strip():
            patch.syntax_valid = False
            patch.status = PatchStatus.FAILED
            return patch

        result = self._check_syntax(patch.fixed_code)
        patch.syntax_valid = result.valid

        if not result.valid:
            patch.status = PatchStatus.FAILED
            patch.explanation += f"\n\n⚠️ 문법 오류: {result.error_message} (라인 {result.error_line})"

        return patch

    def check_batch(self, patches: list[PatchSuggestion]) -> list[PatchSuggestion]:
        """여러 수정안을 일괄 검증"""
        return [self.check(p) for p in patches]

    def _check_syntax(self, code: str) -> CheckResult:
        """Python 코드의 문법을 검증합니다."""
        try:
            ast.parse(code)
            return CheckResult(valid=True)
        except SyntaxError as e:
            return CheckResult(
                valid=False,
                error_message=str(e.msg),
                error_line=e.lineno,
            )

    def check_with_flake8(self, code: str) -> CheckResult:
        """flake8로 코드 스타일까지 검사합니다 (선택적)."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write(code)
            f.flush()
            tmp_path = f.name

        try:
            result = subprocess.run(
                ["flake8", "--select=E9,F63,F7,F82", tmp_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return CheckResult(valid=True)
            else:
                return CheckResult(
                    valid=False,
                    error_message=result.stdout.strip(),
                )
        except FileNotFoundError:
            # flake8 미설치 시 기본 문법 검사로 폴백
            return self._check_syntax(code)
        finally:
            os.unlink(tmp_path)
