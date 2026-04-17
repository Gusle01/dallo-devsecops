"""
파이프라인 통합 테스트 (tests/test_pipeline_integration.py)

정적 분석 결과 → 중복 제거 → 위험도 산정 순서로 호출되는지 검증.
LLM 호출은 mock으로 대체.
"""

import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.schemas import VulnerabilityReport


def _make_vulns():
    """테스트용 취약점 목록 생성 — 중복 포함"""
    code = "query = f'SELECT * FROM users WHERE id = {user_id}'"
    return [
        VulnerabilityReport(
            id="vuln_B608_10", tool="bandit", rule_id="B608",
            severity="HIGH", confidence="HIGH",
            title="SQL Injection", description="SQL injection via f-string",
            file_path="test.py", line_number=10,
            code_snippet=code, function_code=code,
            cwe_id="CWE-89",
        ),
        VulnerabilityReport(
            id="vuln_B608_20", tool="bandit", rule_id="B608",
            severity="HIGH", confidence="HIGH",
            title="SQL Injection", description="SQL injection via f-string",
            file_path="test.py", line_number=20,
            code_snippet=code, function_code=code,
            cwe_id="CWE-89",
        ),
        VulnerabilityReport(
            id="vuln_B303_30", tool="bandit", rule_id="B303",
            severity="MEDIUM", confidence="HIGH",
            title="Weak Hash", description="Use of md5",
            file_path="test.py", line_number=30,
            code_snippet="hashlib.md5(data)", function_code="hashlib.md5(data)",
            cwe_id="CWE-328",
        ),
    ]


class TestPipelineOrder:
    """파이프라인이 정적 분석 → 중복 제거 → 위험도 산정 → LLM 순서로 동작하는지 검증"""

    def test_dedup_then_risk_then_llm(self):
        """중복 제거 → 위험도 산정 → LLM 대표만 전달"""
        from analyzer.deduplicator import deduplicate
        from analyzer.risk_scorer import score_vulnerabilities

        vulns = _make_vulns()

        # Step 1: 중복 제거
        dedup_result = deduplicate(vulns)
        for v in vulns:
            v.duplicate_group_id = dedup_result.group_map.get(v.id, "")
        llm_targets = dedup_result.representatives

        # 동일 rule_id + 동일 코드 → 2개가 1개로 합쳐져야 함
        assert len(llm_targets) == 2  # B608 대표 1 + B303 1
        assert dedup_result.total_deduplicated == 1  # B608 중복 1개 제거

        # Step 2: 위험도 산정
        score_vulnerabilities(vulns)

        # SQL Injection(CWE-89)은 critical, Weak Hash(CWE-328)는 medium
        b608_vuln = next(v for v in vulns if v.rule_id == "B608")
        b303_vuln = next(v for v in vulns if v.rule_id == "B303")
        assert b608_vuln.risk_level == "critical"
        assert b303_vuln.risk_level == "medium"

        # Step 3: LLM에는 대표만 전달 (2건, 원래 3건)
        assert len(llm_targets) < len(vulns)

    def test_duplicate_group_id_assigned(self):
        """중복 그룹 ID가 모든 취약점에 부여되는지 검증"""
        from analyzer.deduplicator import deduplicate

        vulns = _make_vulns()
        dedup_result = deduplicate(vulns)
        for v in vulns:
            v.duplicate_group_id = dedup_result.group_map.get(v.id, "")

        # 모든 취약점에 그룹 ID 할당됨
        for v in vulns:
            assert v.duplicate_group_id != "", f"{v.id}에 그룹 ID 미할당"

        # B608 2개는 같은 그룹
        b608_vulns = [v for v in vulns if v.rule_id == "B608"]
        assert b608_vulns[0].duplicate_group_id == b608_vulns[1].duplicate_group_id

        # B303은 다른 그룹
        b303_vuln = next(v for v in vulns if v.rule_id == "B303")
        assert b303_vuln.duplicate_group_id != b608_vulns[0].duplicate_group_id

    def test_risk_score_persists_on_schema(self):
        """schemas.py의 risk_level, cvss_score 필드가 실제로 채워지는지 검증"""
        from analyzer.risk_scorer import score_vulnerabilities

        vulns = _make_vulns()
        score_vulnerabilities(vulns)

        for v in vulns:
            assert v.risk_level in ("critical", "high", "medium", "low"), \
                f"{v.id}: risk_level={v.risk_level}"
            assert 0 < v.cvss_score <= 10.0, \
                f"{v.id}: cvss_score={v.cvss_score}"

    def test_empty_vulns_no_error(self):
        """취약점 0건이어도 에러 없이 동작"""
        from analyzer.deduplicator import deduplicate
        from analyzer.risk_scorer import score_vulnerabilities

        result = deduplicate([])
        assert len(result.representatives) == 0

        score_vulnerabilities([])  # no error
