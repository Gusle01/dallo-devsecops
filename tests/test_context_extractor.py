"""Context Extractor 테스트"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.bandit_runner import BanditRunner, Vulnerability
from analyzer.context_extractor import ContextExtractor, CodeContext


class TestContextExtractor:
    """ContextExtractor 클래스 테스트"""

    def setup_method(self):
        self.extractor = ContextExtractor(context_lines=10)

    def test_extract_imports(self):
        """import 문이 정상 추출되는지"""
        vuln = Vulnerability(
            tool="bandit", rule_id="B608", severity="HIGH",
            confidence="HIGH", title="sql_injection",
            description="SQL injection", file_path="test_targets/sql_injection.py",
            line_number=10,
        )
        ctx = self.extractor.extract(vuln)
        assert ctx.file_imports  # import 문이 있어야 함

    def test_extract_function(self):
        """함수 전체 코드가 추출되는지"""
        vuln = Vulnerability(
            tool="bandit", rule_id="B602", severity="HIGH",
            confidence="HIGH", title="subprocess_shell",
            description="shell=True", file_path="test_targets/command_injection.py",
            line_number=25,
        )
        ctx = self.extractor.extract(vuln)
        assert ctx.full_function
        assert "def " in ctx.full_function

    def test_extract_batch(self):
        """일괄 추출이 동작하는지"""
        runner = BanditRunner()
        result = runner.run("test_targets/command_injection.py")
        contexts = self.extractor.extract_batch(result.vulnerabilities)

        assert len(contexts) == len(result.vulnerabilities)

    def test_nonexistent_file(self):
        """존재하지 않는 파일에 대한 처리"""
        vuln = Vulnerability(
            tool="bandit", rule_id="B608", severity="HIGH",
            confidence="HIGH", title="test",
            description="test", file_path="nonexistent.py",
            line_number=1,
        )
        ctx = self.extractor.extract(vuln)
        assert ctx.full_function == ""
        assert ctx.file_imports == ""

    def test_to_prompt_context(self):
        """프롬프트 문맥 변환이 동작하는지"""
        vuln = Vulnerability(
            tool="bandit", rule_id="B608", severity="HIGH",
            confidence="HIGH", title="sql_injection",
            description="SQL injection", file_path="test_targets/sql_injection.py",
            line_number=10,
        )
        ctx = self.extractor.extract(vuln)
        prompt = ctx.to_prompt_context()

        assert "취약점 정보" in prompt
        assert "B608" in prompt
