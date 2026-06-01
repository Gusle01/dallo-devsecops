"""
위험도 산정 모듈 (analyzer/risk_scorer.py)

CWE 기반 CVSS 스코어 매핑 + Bandit/Semgrep severity를 종합하여
critical/high/medium/low 4단계로 분류합니다.
"""

import json
import os
import logging
from functools import lru_cache

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

# 수정 우선순위(fix priority) 라벨
# P1: 즉시 수정, P2: 빠른 시일 내 수정, P3: 일정에 따라 수정
_PRIORITY_LABELS = {
    "P1": "즉시 수정",
    "P2": "우선 수정",
    "P3": "일정 내 수정",
}


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


@lru_cache(maxsize=1)
def _load_cwe_cve_map() -> dict:
    """shared/cwe_cve_map.json에서 CWE → 대표(참고) CVE 매핑을 로드합니다."""
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "shared", "cwe_cve_map.json"
    )
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return {k: v for k, v in data.items() if not k.startswith("_") and isinstance(v, list)}
        except Exception:
            return {}
    return {}


def compute_fix_priority(cvss: float, exploitability: str = "", confidence: str = "") -> dict:
    """
    CVSS 점수 + 공격 가능성 + 탐지 신뢰도로 수정 우선순위를 산정합니다.

    Returns:
        {"fix_priority": "P1|P2|P3", "priority_label": str}
    """
    exploit = (exploitability or "").lower()
    conf = (confidence or "").upper()

    # 기본은 CVSS 구간 기반
    if cvss >= 9.0:
        priority = "P1"
    elif cvss >= 7.0:
        priority = "P2"
    else:
        priority = "P3"

    # 공격 가능성이 높으면 한 단계 상향, 낮으면(+낮은 신뢰도) 한 단계 하향
    if exploit == "high" and priority == "P2":
        priority = "P1"
    elif exploit == "low" and conf == "LOW" and priority == "P1":
        priority = "P2"

    return {"fix_priority": priority, "priority_label": _PRIORITY_LABELS.get(priority, "")}


def score_risk(vuln, external_cwe_map: dict = None, external_cve_map: dict = None) -> dict:
    """
    취약점의 위험도를 산정합니다.

    Args:
        vuln: VulnerabilityReport 객체 (또는 dict)
        external_cwe_map: 외부 CWE→CVSS 매핑 (없으면 내장 테이블 사용)
        external_cve_map: CWE→참고 CVE 매핑 (없으면 파일에서 로드)

    Returns:
        {"risk_level", "cvss_score", "cve_ids", "fix_priority", "priority_label", "factors"}
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

    cvss = round(cvss, 1)

    # 4. 관련(참고) CVE 매핑 — 의존성 취약점이면 자체 CVE 우선
    existing_cve = vuln.cve_ids if hasattr(vuln, "cve_ids") else (vuln.get("cve_ids") if isinstance(vuln, dict) else None)
    if existing_cve:
        cve_ids = list(existing_cve)
    else:
        cve_map = external_cve_map if external_cve_map is not None else _load_cwe_cve_map()
        cve_ids = list(cve_map.get(cwe_id, [])) if cwe_id else []
    if cve_ids:
        factors.append(f"관련 참고 CVE {len(cve_ids)}건")

    # 5. 수정 우선순위 — exploitability는 red_blue enrich 단계에서 채워지므로
    #    여기서는 confidence 기반으로 산정하고, 이후 단계에서 보정 가능.
    exploitability = vuln.exploitability if hasattr(vuln, "exploitability") else (vuln.get("exploitability", "") if isinstance(vuln, dict) else "")
    priority = compute_fix_priority(cvss, exploitability, confidence)

    return {
        "risk_level": risk_level,
        "cvss_score": cvss,
        "cve_ids": cve_ids,
        "fix_priority": priority["fix_priority"],
        "priority_label": priority["priority_label"],
        "factors": factors,
    }


def score_vulnerabilities(vulnerabilities: list) -> list:
    """
    취약점 목록 전체에 위험도를 산정합니다.

    각 취약점 객체에 risk_level, cvss_score, cve_ids, fix_priority 속성을 추가하고 반환합니다.
    """
    external_map = _load_external_cwe_map()
    cve_map = _load_cwe_cve_map()

    for vuln in vulnerabilities:
        result = score_risk(vuln, external_map, cve_map)
        for attr in ("risk_level", "cvss_score", "cve_ids", "fix_priority", "priority_label"):
            if hasattr(vuln, attr):
                setattr(vuln, attr, result[attr])
        # dict 타입 지원
        if isinstance(vuln, dict):
            vuln["risk_level"] = result["risk_level"]
            vuln["cvss_score"] = result["cvss_score"]
            vuln["cve_ids"] = result["cve_ids"]
            vuln["fix_priority"] = result["fix_priority"]
            vuln["priority_label"] = result["priority_label"]

    return vulnerabilities
