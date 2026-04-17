"""
CI/CD 보안 게이트 테스트 (tests/test_ci_gate.py)
"""

import os
import sys
import json
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.ci_gate import check_gate, load_gate_config


def _write_result(vulns):
    """임시 결과 파일 생성"""
    data = {"vulnerabilities": vulns}
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    return path


class TestCIGate:
    def test_pass_no_critical(self):
        path = _write_result([
            {"severity": "HIGH", "rule_id": "B608"},
            {"severity": "MEDIUM", "rule_id": "B303"},
        ])
        config = {"critical_threshold": 1, "high_threshold": 5}
        passed, msg = check_gate(path, config)
        assert passed is True
        assert "PASSED" in msg
        os.unlink(path)

    def test_fail_critical(self):
        path = _write_result([
            {"severity": "CRITICAL", "rule_id": "B601"},
        ])
        config = {"critical_threshold": 1, "high_threshold": 5}
        passed, msg = check_gate(path, config)
        assert passed is False
        assert "FAILED" in msg
        os.unlink(path)

    def test_fail_high_threshold(self):
        vulns = [{"severity": "HIGH", "rule_id": f"B{i}"} for i in range(6)]
        path = _write_result(vulns)
        config = {"critical_threshold": 1, "high_threshold": 5}
        passed, msg = check_gate(path, config)
        assert passed is False
        os.unlink(path)

    def test_pass_below_threshold(self):
        vulns = [{"severity": "HIGH", "rule_id": f"B{i}"} for i in range(4)]
        path = _write_result(vulns)
        config = {"critical_threshold": 1, "high_threshold": 5}
        passed, msg = check_gate(path, config)
        assert passed is True
        os.unlink(path)

    def test_missing_file_passes(self):
        config = {"critical_threshold": 1, "high_threshold": 5}
        passed, msg = check_gate("/nonexistent/file.json", config)
        assert passed is True

    def test_risk_level_used(self):
        """risk_level 필드가 있으면 severity 대신 사용"""
        path = _write_result([
            {"severity": "HIGH", "risk_level": "critical", "rule_id": "B608"},
        ])
        config = {"critical_threshold": 1, "high_threshold": 5}
        passed, msg = check_gate(path, config)
        assert passed is False  # risk_level=critical
        os.unlink(path)

    def test_env_override(self):
        os.environ["DALLO_GATE_CRITICAL_THRESHOLD"] = "3"
        config = load_gate_config()
        assert config["critical_threshold"] == 3
        del os.environ["DALLO_GATE_CRITICAL_THRESHOLD"]
