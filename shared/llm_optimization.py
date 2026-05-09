"""
LLM speed optimization helpers.

The static analyzer can still scan broadly, but expensive LLM remediation
should be scoped to the highest-value subset: selected CVE/CWE/rules, capped
target counts, and trimmed code context.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field


SCOPE_ALIASES = {
    "SQLI": "CWE-89",
    "SQL-INJECTION": "CWE-89",
    "SQL_INJECTION": "CWE-89",
    "COMMAND-INJECTION": "CWE-78",
    "COMMAND_INJECTION": "CWE-78",
    "CMDI": "CWE-78",
    "XSS": "CWE-79",
    "AUTH-BYPASS": "CWE-288",
    "AUTH_BYPASS": "CWE-288",
    "AUTHENTICATION-BYPASS": "CWE-288",
    "DESERIALIZATION": "CWE-502",
    "PATH-TRAVERSAL": "CWE-22",
    "PATH_TRAVERSAL": "CWE-22",
    "HARDCODED-SECRET": "CWE-798",
    "HARDCODED_SECRET": "CWE-798",
}


@dataclass
class LLMOptimizationConfig:
    enabled: bool = True
    cve_scope: list[str] = field(default_factory=list)
    cwe_scope: list[str] = field(default_factory=list)
    rule_scope: list[str] = field(default_factory=list)
    max_targets: int = 10
    max_context_chars: int = 2400
    batch_enabled: bool = True
    batch_size: int = 5


def optimize_llm_targets(vulnerabilities: list, config: LLMOptimizationConfig) -> tuple[list, dict]:
    """Filter and trim vulnerability objects before LLM calls."""
    original_count = len(vulnerabilities)
    targets = list(vulnerabilities)

    if config.enabled:
        targets = _filter_by_scope(targets, config)
        targets = sorted(targets, key=_priority_key)
        if config.max_targets and config.max_targets > 0:
            targets = targets[:config.max_targets]

    targets = [deepcopy(vuln) for vuln in targets]
    for vuln in targets:
        trim_vulnerability_context(vuln, config.max_context_chars)

    summary = {
        "enabled": config.enabled,
        "original_targets": original_count,
        "selected_targets": len(targets),
        "skipped_targets": max(original_count - len(targets), 0),
        "max_context_chars": config.max_context_chars,
        "batch_enabled": config.batch_enabled,
        "batch_size": config.batch_size,
        "scope": {
            "cve": config.cve_scope,
            "cwe": config.cwe_scope,
            "rule": config.rule_scope,
        },
    }
    return targets, summary


def trim_vulnerability_context(vuln, max_chars: int):
    """Keep the LLM prompt focused around the vulnerable snippet."""
    if not max_chars or max_chars <= 0:
        return

    for attr in ("function_code", "code_snippet", "file_imports"):
        value = getattr(vuln, attr, "")
        if value and len(value) > max_chars:
            setattr(vuln, attr, _center_trim(value, max_chars))


def scoped_copy(vuln, max_chars: int):
    """Return a deepcopy with context trimmed, useful for tests/callers."""
    cloned = deepcopy(vuln)
    trim_vulnerability_context(cloned, max_chars)
    return cloned


def _filter_by_scope(vulnerabilities: list, config: LLMOptimizationConfig) -> list:
    cve_scope = {_norm(x) for x in config.cve_scope if x}
    cwe_scope = {_scope_token(x) for x in config.cwe_scope if x}
    rule_scope = {_norm(x) for x in config.rule_scope if x}

    if not cve_scope and not cwe_scope and not rule_scope:
        return vulnerabilities

    selected = []
    for vuln in vulnerabilities:
        cwe = _norm(getattr(vuln, "cwe_id", ""))
        rule = _norm(getattr(vuln, "rule_id", ""))
        title = _norm(getattr(vuln, "title", ""))
        desc = _norm(getattr(vuln, "description", ""))
        more = _norm(getattr(vuln, "more_info", ""))
        haystack = " ".join([cwe, rule, title, desc, more])

        if cwe_scope and cwe in cwe_scope:
            selected.append(vuln)
        elif rule_scope and rule in rule_scope:
            selected.append(vuln)
        elif cve_scope and any(cve in haystack for cve in cve_scope):
            selected.append(vuln)

    return selected


def _priority_key(vuln) -> tuple:
    risk = _risk_rank(getattr(vuln, "risk_level", ""))
    severity = _severity_rank(getattr(vuln, "severity", ""))
    cvss = float(getattr(vuln, "cvss_score", 0.0) or 0.0)
    return (-risk, -severity, -cvss, getattr(vuln, "file_path", ""), getattr(vuln, "line_number", 0))


def _risk_rank(value: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(value).lower(), 0)


def _severity_rank(value: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(value).upper(), 0)


def _center_trim(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    head = text[:half].rstrip()
    tail = text[-(max_chars - half):].lstrip()
    return f"{head}\n# ... context trimmed for faster LLM remediation ...\n{tail}"


def _norm(value: str) -> str:
    return str(value or "").strip().upper()


def _scope_token(value: str) -> str:
    token = _norm(value)
    return SCOPE_ALIASES.get(token, token)
