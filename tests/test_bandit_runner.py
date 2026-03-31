"""Bandit Runner 테스트"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.bandit_runner import BanditRunner, run_bandit_analysis


class TestBanditRunner:
    """BanditRunner 클래스 테스트"""

    def test_run_on_test_targets(self):
        """test_targets/ 디렉토리 분석이 정상 동작하는지"""
        runner = BanditRunner(config_path="config/bandit.yml")
        result = runner.run("test_targets/", output_path=None)

        assert result.error is None
        assert result.total_issues > 0
        assert result.tool == "bandit"

    def test_detects_sql_injection(self):
        """SQL injection 취약점이 탐지되는지"""
        runner = BanditRunner()
        result = runner.run("test_targets/sql_injection.py")

        assert result.total_issues > 0
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        assert "B608" in rule_ids  # hardcoded_sql_expressions

    def test_detects_command_injection(self):
        """Command injection 취약점이 탐지되는지"""
        runner = BanditRunner()
        result = runner.run("test_targets/command_injection.py")

        assert result.total_issues > 0
        rule_ids = [v.rule_id for v in result.vulnerabilities]
        assert any(r in rule_ids for r in ["B602", "B605"])

    def test_detects_hardcoded_secrets(self):
        """하드코딩된 비밀번호가 탐지되는지"""
        runner = BanditRunner()
        result = runner.run("test_targets/hardcoded_secrets.py")

        assert result.total_issues > 0

    def test_vulnerability_fields(self):
        """취약점 객체의 필수 필드가 채워져 있는지"""
        runner = BanditRunner()
        result = runner.run("test_targets/sql_injection.py")

        for vuln in result.vulnerabilities:
            assert vuln.tool == "bandit"
            assert vuln.rule_id
            assert vuln.severity in ("HIGH", "MEDIUM", "LOW")
            assert vuln.file_path
            assert vuln.line_number > 0
            assert vuln.title

    def test_severity_counts(self):
        """심각도별 카운트가 정확한지"""
        runner = BanditRunner()
        result = runner.run("test_targets/")

        total = result.high_count + result.medium_count + result.low_count
        assert total == result.total_issues

    def test_nonexistent_target(self):
        """존재하지 않는 경로는 결과 0건"""
        runner = BanditRunner()
        result = runner.run("nonexistent_path/")

        # Bandit은 존재하지 않는 경로도 JSON 반환 (errors 필드에 기록)
        assert result.total_issues == 0

    def test_convenience_function(self):
        """run_bandit_analysis 편의 함수 테스트"""
        result = run_bandit_analysis("test_targets/sql_injection.py")
        assert result.total_issues > 0
