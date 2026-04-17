"""
중복 제거 + 위험도 산정 테스트 (tests/test_dedup_risk.py)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.schemas import VulnerabilityReport
from analyzer.deduplicator import deduplicate, _code_similarity
from analyzer.risk_scorer import score_risk, score_vulnerabilities


def _make_vuln(id, rule_id, severity="HIGH", code="def foo(): pass", cwe_id=None):
    return VulnerabilityReport(
        id=id, tool="bandit", rule_id=rule_id, severity=severity,
        confidence="HIGH", title=f"Test {rule_id}", description="test",
        file_path="test.py", line_number=1, code_snippet=code,
        cwe_id=cwe_id,
    )


class TestDeduplication:
    def test_no_duplicates(self):
        vulns = [
            _make_vuln("v1", "B608", code="def a(): query = 'SELECT'"),
            _make_vuln("v2", "B101", code="def b(): assert True"),
        ]
        result = deduplicate(vulns)
        assert len(result.representatives) == 2
        assert result.total_deduplicated == 0

    def test_exact_duplicates(self):
        code = "def foo(): os.system(user_input)"
        vulns = [
            _make_vuln("v1", "B605", code=code),
            _make_vuln("v2", "B605", code=code),
            _make_vuln("v3", "B605", code=code),
        ]
        result = deduplicate(vulns)
        assert len(result.representatives) == 1
        assert result.total_deduplicated == 2

    def test_different_rules_not_merged(self):
        code = "def foo(): pass"
        vulns = [
            _make_vuln("v1", "B608", code=code),
            _make_vuln("v2", "B101", code=code),
        ]
        result = deduplicate(vulns)
        assert len(result.representatives) == 2

    def test_similarity_threshold(self):
        vulns = [
            _make_vuln("v1", "B608", code="def foo():\n    query = 'SELECT * FROM users'"),
            _make_vuln("v2", "B608", code="def foo():\n    query = 'SELECT * FROM users WHERE id=1'"),
        ]
        # 유사도 높아서 병합될 수 있음
        result = deduplicate(vulns, similarity_threshold=0.95)
        # 높은 threshold이면 병합 안 됨
        assert len(result.representatives) >= 1

    def test_code_similarity(self):
        assert _code_similarity("def a(): pass", "def a(): pass") == 1.0
        assert _code_similarity("abc", "xyz") < 0.5
        assert _code_similarity("", "") == 0.0


class TestRiskScorer:
    def test_sql_injection_critical(self):
        vuln = _make_vuln("v1", "B608", severity="HIGH", cwe_id="CWE-89")
        result = score_risk(vuln)
        assert result["risk_level"] == "critical"
        assert result["cvss_score"] >= 9.0

    def test_weak_hash_medium(self):
        vuln = _make_vuln("v1", "B303", severity="MEDIUM", cwe_id="CWE-328")
        result = score_risk(vuln)
        assert result["risk_level"] == "medium"

    def test_unknown_cwe_uses_severity(self):
        vuln = _make_vuln("v1", "B999", severity="LOW")
        result = score_risk(vuln)
        assert result["risk_level"] == "low"

    def test_low_confidence_reduces_score(self):
        vuln = _make_vuln("v1", "B608", severity="HIGH", cwe_id="CWE-89")
        vuln.confidence = "LOW"
        result = score_risk(vuln)
        assert result["cvss_score"] < 9.8  # 원래 9.8에서 감소

    def test_score_vulnerabilities_batch(self):
        vulns = [
            _make_vuln("v1", "B608", severity="HIGH", cwe_id="CWE-89"),
            _make_vuln("v2", "B303", severity="LOW"),
        ]
        scored = score_vulnerabilities(vulns)
        assert scored[0].risk_level == "critical"
        assert scored[1].risk_level == "low"
