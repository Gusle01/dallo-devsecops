"""
위험도 산정 모듈 (analyzer/risk_scorer.py)

CWE 기반 CVSS 스코어 매핑 + Bandit/Semgrep severity를 종합하여
critical/high/medium/low 4단계로 분류합니다.
"""

import json
import os
import logging

logger = logging.getLogger(__name__)

# CWE → 기본 CVSS 스코어 매핑 (주요 취약점만, 나머지는 severity 기반)
_CWE_CVSS_MAP = {
    "CWE-78":  9.8,   # OS Command Injection
    "CWE-89":  9.8,   # SQL Injection
    "CWE-94":  9.8,   # Code Injection
    "CWE-502": 9.8,   # Deserialization
    "CWE-798": 9.1,   # Hardcoded Credentials
    "CWE-79":  6.1,   # XSS
    "CWE-22":  7.5,   # Path Traversal
    "CWE-200": 5.3,   # Information Exposure
    "CWE-327": 5.9,   # Weak Crypto
    "CWE-328": 5.3,   # Weak Hash
    "CWE-330": 5.3,   # Insecure Random
    "CWE-611": 7.5,   # XXE
    "CWE-918": 9.1,   # SSRF
    "CWE-287": 9.8,   # Auth Bypass
    "CWE-306": 9.8,   # Missing Auth
    "CWE-352": 8.8,   # CSRF
    "CWE-434": 9.8,   # Unrestricted Upload
    "CWE-862": 8.2,   # Missing Authorization
}

# severity 문자열 → 기본 CVSS 범위
_SEVERITY_BASE_CVSS = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
}

# CVSS → risk_level 매핑
_CVSS_TO_RISK = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.0, "low"),
]


def _load_external_cwe_map() -> dict:
    """shared/cwe_severity.json에서 추가 CWE 매핑을 로드합니다."""
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "shared", "cwe_severity.json"
    )
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def score_risk(vuln, external_cwe_map: dict = None) -> dict:
    """
    취약점의 위험도를 산정합니다.

    Args:
        vuln: VulnerabilityReport 객체 (또는 dict)
        external_cwe_map: 외부 CWE→CVSS 매핑 (없으면 내장 테이블 사용)

    Returns:
        {"risk_level": "critical|high|medium|low", "cvss_score": float, "factors": [...]}
    """
    cwe_id = vuln.cwe_id if hasattr(vuln, "cwe_id") else vuln.get("cwe_id", "")
    severity = (vuln.severity if hasattr(vuln, "severity") else vuln.get("severity", "")).upper()
    confidence = (vuln.confidence if hasattr(vuln, "confidence") else vuln.get("confidence", "")).upper()

    factors = []
    cvss = 0.0

    # 1. CWE 기반 CVSS
    cwe_map = {**_CWE_CVSS_MAP, **(external_cwe_map or {})}
    if cwe_id and cwe_id in cwe_map:
        cvss = cwe_map[cwe_id]
        factors.append(f"CWE 매핑 ({cwe_id} → CVSS {cvss})")
    else:
        # severity 기반 fallback
        cvss = _SEVERITY_BASE_CVSS.get(severity, 5.0)
        factors.append(f"Severity 기반 (→ CVSS {cvss})")

    # 2. Confidence 보정 (LOW confidence면 점수 하향)
    if confidence == "LOW":
        cvss *= 0.8
        factors.append("낮은 신뢰도로 0.8배 적용")
    elif confidence == "HIGH":
        cvss *= 1.05
        cvss = min(cvss, 10.0)
        factors.append("높은 신뢰도로 1.05배 적용")

    # 3. risk_level 결정
    risk_level = "low"
    for threshold, level in _CVSS_TO_RISK:
        if cvss >= threshold:
            risk_level = level
            break

    return {
        "risk_level": risk_level,
        "cvss_score": round(cvss, 1),
        "factors": factors,
    }


def score_vulnerabilities(vulnerabilities: list) -> list:
    """
    취약점 목록 전체에 위험도를 산정합니다.

    각 취약점 객체에 risk_level, cvss_score 속성을 추가하고 반환합니다.
    """
    external_map = _load_external_cwe_map()

    for vuln in vulnerabilities:
        result = score_risk(vuln, external_map)
        if hasattr(vuln, "risk_level"):
            vuln.risk_level = result["risk_level"]
        if hasattr(vuln, "cvss_score"):
            vuln.cvss_score = result["cvss_score"]
        # dict 타입 지원
        if isinstance(vuln, dict):
            vuln["risk_level"] = result["risk_level"]
            vuln["cvss_score"] = result["cvss_score"]

    return vulnerabilities
