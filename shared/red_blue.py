"""
Red Team / Blue Team security posture helpers.

This module keeps the attack/defense framing close to the shared data
contract without changing the database schema. The API and dashboard can
derive a red-blue view from existing scan and patch records.
"""

from __future__ import annotations

from copy import deepcopy


_ATTACK_TEMPLATES = {
    "CWE-89": {
        "vector": "SQL injection",
        "scenario": "An attacker may inject crafted input into a database query and read, modify, or delete records.",
        "impact": "data exposure or unauthorized data manipulation",
        "defense": "Use parameterized queries or ORM-bound values and reject unsafe query construction.",
        "controlled_input": "request parameter or user-controlled value used in query construction",
        "vulnerable_action": "dynamic SQL execution",
        "attack_goal": "read, modify, or delete unauthorized database records",
    },
    "CWE-78": {
        "vector": "command injection",
        "scenario": "An attacker may pass shell metacharacters through user-controlled input and execute unintended commands.",
        "impact": "remote command execution or host compromise",
        "defense": "Avoid shell execution, pass arguments as arrays, and validate input against an allowlist.",
        "controlled_input": "request parameter or user-controlled value passed to a shell command",
        "vulnerable_action": "command execution",
        "attack_goal": "execute unintended operating system commands",
    },
    "CWE-79": {
        "vector": "cross-site scripting",
        "scenario": "An attacker may inject script into a response rendered by another user's browser.",
        "impact": "session theft, account actions, or client-side data exposure",
        "defense": "Escape output, sanitize HTML, and use framework-safe rendering primitives.",
        "controlled_input": "user-controlled text rendered into HTML",
        "vulnerable_action": "unsafe HTML/script rendering",
        "attack_goal": "execute script in another user's browser",
    },
    "CWE-798": {
        "vector": "hardcoded secret exposure",
        "scenario": "An attacker who gains source access may reuse embedded credentials against external systems.",
        "impact": "credential leakage and lateral movement",
        "defense": "Move secrets to environment variables or a secret manager and rotate exposed values.",
        "controlled_input": "source code or artifact access",
        "vulnerable_action": "secret reuse from code",
        "attack_goal": "reuse exposed credentials",
    },
    "CWE-328": {
        "vector": "weak cryptography",
        "scenario": "An attacker may brute-force or collide weak hashes used for security-sensitive values.",
        "impact": "password or token recovery",
        "defense": "Use modern password hashing or SHA-256+ only where cryptographic hashes are appropriate.",
        "controlled_input": "hashable secret or token material",
        "vulnerable_action": "weak digest generation",
        "attack_goal": "recover or collide sensitive values",
    },
    "CWE-502": {
        "vector": "unsafe deserialization",
        "scenario": "An attacker may submit crafted serialized data that triggers code execution or object injection.",
        "impact": "remote code execution or privilege abuse",
        "defense": "Avoid unsafe deserializers for untrusted input and use strict schema validation.",
        "controlled_input": "serialized payload",
        "vulnerable_action": "unsafe object deserialization",
        "attack_goal": "trigger object injection or code execution",
    },
    "CWE-22": {
        "vector": "path traversal",
        "scenario": "An attacker may manipulate file paths to read or overwrite files outside the intended directory.",
        "impact": "sensitive file disclosure or arbitrary file write",
        "defense": "Normalize paths, enforce base-directory containment, and reject traversal sequences.",
        "controlled_input": "file path segment",
        "vulnerable_action": "filesystem access",
        "attack_goal": "read or write files outside the intended directory",
    },
    "CWE-288": {
        "vector": "authentication bypass",
        "scenario": "An attacker may control an account identifier or alternate verification path and mark another account as verified.",
        "impact": "unauthorized account verification or access",
        "defense": "Use the authenticated server-side principal, bind verification to the session owner, and reject request-controlled account identity.",
        "controlled_input": "request-controlled account identifier",
        "vulnerable_action": "server-side verification state update",
        "attack_goal": "bypass account verification for another user",
    },
}


def enrich_vulnerability(vuln: dict) -> dict:
    """Return a vulnerability dict with Red Team analysis fields."""
    item = deepcopy(vuln)
    cwe_id = item.get("cwe_id") or ""
    tpl = _ATTACK_TEMPLATES.get(cwe_id, _generic_template(item))
    risk = (item.get("risk_level") or item.get("severity") or "unknown").lower()

    item.setdefault("red_team_phase", "attack_surface_mapping")
    item.setdefault("attack_vector", tpl["vector"])
    item.setdefault("attack_scenario", tpl["scenario"])
    item.setdefault("security_impact", tpl["impact"])
    item.setdefault("blue_team_strategy", tpl["defense"])
    item.setdefault("exploitability", _exploitability(risk, item.get("confidence", "")))
    item.setdefault("attack_plan", build_attack_plan(item, tpl))
    return item


def enrich_patch(patch: dict, vuln: dict | None = None) -> dict:
    """Return a patch dict with Blue Team action fields."""
    item = deepcopy(patch)
    vuln = vuln or {}
    sec = item.get("security_revalidation") or {}
    status = (item.get("status") or "").replace("PatchStatus.", "").lower()

    if sec.get("passed") or status == "verified":
        outcome = "validated_defense"
    elif status == "failed" or sec.get("introduced_count", 0) > 0:
        outcome = "needs_review"
    elif item.get("fixed_code"):
        outcome = "drafted_defense"
    else:
        outcome = "not_generated"

    if not item.get("blue_team_phase"):
        item["blue_team_phase"] = "remediation"
    if not item.get("defense_strategy"):
        item["defense_strategy"] = vuln.get("blue_team_strategy") or "Generate a secure refactoring and validate it with syntax and security checks."
    if not item.get("defense_outcome"):
        item["defense_outcome"] = outcome
    if not item.get("residual_risk"):
        item["residual_risk"] = _residual_risk(item["defense_outcome"], sec)
    if not item.get("defense_plan"):
        item["defense_plan"] = build_defense_plan(item, vuln, item["defense_outcome"])
    return item


def build_red_blue_summary(vulnerabilities: list[dict], patches: list[dict]) -> dict:
    """Build a compact red/blue posture summary for API and reports."""
    vulns = [enrich_vulnerability(v) for v in vulnerabilities]
    vuln_map = {v.get("id"): v for v in vulns}
    enriched_patches = [enrich_patch(p, vuln_map.get(p.get("vulnerability_id"))) for p in patches]

    attack_surface = {
        "total_findings": len(vulns),
        "critical_or_high": sum(1 for v in vulns if (v.get("risk_level") or v.get("severity", "")).lower() in ("critical", "high")),
        "unique_cwe": len({v.get("cwe_id") for v in vulns if v.get("cwe_id")}),
        "affected_files": len({v.get("file_path") for v in vulns if v.get("file_path")}),
    }
    defense = {
        "patches_generated": sum(1 for p in enriched_patches if p.get("fixed_code")),
        "patches_verified": sum(1 for p in enriched_patches if p.get("defense_outcome") == "validated_defense"),
        "patches_needing_review": sum(1 for p in enriched_patches if p.get("defense_outcome") == "needs_review"),
    }
    comparison = build_defense_comparison(vulns, enriched_patches)
    attack_paths = build_attack_paths(vulns, enriched_patches)

    return {
        "mode": "red_blue",
        "system_label": "AI-based attack and defense analysis system",
        "red_team": attack_surface,
        "blue_team": defense,
        "comparison": comparison,
        "attack_paths": attack_paths,
    }


def build_attack_plan(vuln: dict, template: dict | None = None) -> dict:
    """Build a structured Red Team attack plan from a finding."""
    template = template or _ATTACK_TEMPLATES.get(vuln.get("cwe_id") or "", _generic_template(vuln))
    evidence = _evidence(vuln)
    entry_point = _entry_point(vuln)
    controlled_input = _controlled_input(vuln, template)
    vulnerable_action = template.get("vulnerable_action", "security-sensitive operation")

    return {
        "finding_id": vuln.get("id", ""),
        "status": "OPEN",
        "attack_goal": template.get("attack_goal", template.get("impact", "abuse the vulnerable behavior")),
        "entry_point": entry_point,
        "controlled_input": controlled_input,
        "trust_boundary": _trust_boundary(vuln, controlled_input),
        "vulnerable_action": vulnerable_action,
        "exploit_steps": [
            f"Reach {entry_point}.",
            f"Control {controlled_input}.",
            f"Trigger {vulnerable_action}.",
            f"Achieve {template.get('impact', 'security impact')}.",
        ],
        "impact": template.get("impact", ""),
        "evidence": evidence,
        "attack_path": f"{controlled_input} -> {vulnerable_action}",
    }


def build_defense_plan(patch: dict, vuln: dict, outcome: str) -> dict:
    """Build a structured Blue Team defense plan linked to an attack path."""
    strategy = patch.get("defense_strategy") or vuln.get("blue_team_strategy") or "Apply a focused secure refactor."
    status = _defense_status(outcome)
    attack_plan = vuln.get("attack_plan") or build_attack_plan(vuln)

    return {
        "finding_id": patch.get("vulnerability_id") or vuln.get("id", ""),
        "status": status,
        "defense_goal": _defense_goal(vuln),
        "strategy": strategy,
        "code_change": _code_change_summary(patch),
        "validation": _validation_steps(patch),
        "residual_risk": patch.get("residual_risk") or _residual_risk(outcome, patch.get("security_revalidation") or {}),
        "blocked_attack_path": attack_plan.get("attack_path", ""),
    }


def build_attack_paths(vulnerabilities: list[dict], patches: list[dict]) -> list[dict]:
    """Merge attack and defense data into OPEN/BLOCKED path records."""
    patch_map: dict[str, list[dict]] = {}
    for patch in patches:
        patch_map.setdefault(patch.get("vulnerability_id", ""), []).append(patch)

    rows = []
    for vuln in vulnerabilities:
        attack_plan = vuln.get("attack_plan") or build_attack_plan(vuln)
        related = patch_map.get(vuln.get("id", ""), [])
        best_patch = _best_patch(related)
        defense_plan = best_patch.get("defense_plan") if best_patch else None
        status = defense_plan.get("status") if defense_plan else "OPEN"
        rows.append({
            "finding_id": vuln.get("id", ""),
            "rule_id": vuln.get("rule_id", ""),
            "title": vuln.get("title", ""),
            "cwe_id": vuln.get("cwe_id"),
            "file_path": vuln.get("file_path", ""),
            "line_number": vuln.get("line_number", 0),
            "attack_path": attack_plan.get("attack_path", ""),
            "attack_goal": attack_plan.get("attack_goal", ""),
            "status": status,
            "defense": defense_plan.get("strategy") if defense_plan else vuln.get("blue_team_strategy", ""),
            "residual_risk": defense_plan.get("residual_risk") if defense_plan else "high",
        })
    return rows


def build_defense_comparison(vulnerabilities: list[dict], patches: list[dict]) -> dict:
    """Estimate before/after posture using patch revalidation evidence when available."""
    before_total = len(vulnerabilities)
    removed = 0
    introduced = 0

    for patch in patches:
        sec = patch.get("security_revalidation") or {}
        if sec:
            removed_count = int(sec.get("removed_count") or 0)
            if sec.get("passed") and removed_count == 0 and patch.get("fixed_code"):
                removed_count = 1
            removed += removed_count
            introduced += int(sec.get("introduced_count") or 0)
        elif patch.get("defense_outcome") == "validated_defense":
            removed += 1

    removed = min(removed, before_total)
    after_total = max(before_total - removed + introduced, 0)
    reduction = round((removed / before_total) * 100, 1) if before_total else 0.0

    return {
        "before_total": before_total,
        "after_total": after_total,
        "fixed_count": removed,
        "remaining_count": max(before_total - removed, 0),
        "introduced_count": introduced,
        "risk_reduction_percent": reduction,
    }


def _generic_template(vuln: dict) -> dict:
    title = (vuln.get("title") or vuln.get("rule_id") or "security weakness").lower()
    return {
        "vector": title,
        "scenario": "An attacker may abuse this weakness depending on reachability, input control, and deployed context.",
        "impact": "increased application security risk",
        "defense": "Apply a minimal secure refactor, validate behavior, and rescan the changed code.",
        "controlled_input": "user-controlled input",
        "vulnerable_action": "security-sensitive operation",
        "attack_goal": "abuse the vulnerable behavior",
    }


def _exploitability(risk: str, confidence: str) -> str:
    confidence = (confidence or "").upper()
    if risk in ("critical", "high") and confidence != "LOW":
        return "high"
    if risk in ("medium", "high"):
        return "medium"
    return "low"


def _residual_risk(outcome: str, sec: dict) -> str:
    if outcome == "validated_defense":
        return "low"
    if sec.get("introduced_count", 0) > 0:
        return "high"
    if outcome == "drafted_defense":
        return "medium"
    return "unknown"


def _defense_status(outcome: str) -> str:
    if outcome == "validated_defense":
        return "BLOCKED"
    if outcome == "drafted_defense":
        return "MITIGATING"
    if outcome == "needs_review":
        return "REVIEW"
    return "OPEN"


def _best_patch(patches: list[dict]) -> dict | None:
    if not patches:
        return None
    order = {"validated_defense": 0, "drafted_defense": 1, "needs_review": 2, "not_generated": 3}
    return sorted(patches, key=lambda p: order.get(p.get("defense_outcome", ""), 9))[0]


def _evidence(vuln: dict) -> str:
    code = (vuln.get("code_snippet") or vuln.get("function_code") or "").strip()
    if not code:
        return f"{vuln.get('file_path', '')}:{vuln.get('line_number', '')}"
    first = code.splitlines()[0].strip()
    return first[:180]


def _entry_point(vuln: dict) -> str:
    text = "\n".join([
        vuln.get("function_code") or "",
        vuln.get("code_snippet") or "",
        vuln.get("description") or "",
    ])
    for marker in ("@PostMapping", "@GetMapping", "@RequestMapping"):
        idx = text.find(marker)
        if idx >= 0:
            line = text[idx:].splitlines()[0].strip()
            return line[:120]
    return f"{vuln.get('file_path', 'unknown')}:{vuln.get('line_number', 0)}"


def _controlled_input(vuln: dict, template: dict) -> str:
    text = "\n".join([vuln.get("function_code") or "", vuln.get("code_snippet") or ""])
    if "@RequestParam String userId" in text:
        return "HTTP request parameter userId"
    if "req.query" in text:
        return "HTTP query parameter"
    if "request" in text.lower():
        return "HTTP request input"
    return template.get("controlled_input", "user-controlled input")


def _trust_boundary(vuln: dict, controlled_input: str) -> str:
    if "HTTP" in controlled_input:
        return "HTTP request -> server-side authorization/session state"
    if vuln.get("cwe_id") == "CWE-89":
        return "application input -> database query"
    if vuln.get("cwe_id") == "CWE-78":
        return "application input -> operating system command"
    return "untrusted input -> trusted operation"


def _defense_goal(vuln: dict) -> str:
    cwe = vuln.get("cwe_id")
    if cwe == "CWE-288":
        return "Remove request-controlled identity from account verification."
    if cwe == "CWE-89":
        return "Prevent user input from changing SQL query structure."
    if cwe == "CWE-78":
        return "Prevent user input from controlling command execution."
    return f"Block {vuln.get('attack_vector') or vuln.get('title') or 'the attack path'}."


def _code_change_summary(patch: dict) -> str:
    if not patch.get("fixed_code"):
        return "No code change generated yet."
    fix_type = patch.get("fix_type") or "recommended"
    return f"{fix_type} secure refactor generated by LLM."


def _validation_steps(patch: dict) -> list[str]:
    steps = []
    if patch.get("syntax_valid") is True:
        steps.append("syntax_check: passed")
    elif patch.get("syntax_valid") is False:
        steps.append("syntax_check: failed")
    else:
        steps.append("syntax_check: pending")

    sec = patch.get("security_revalidation") or {}
    if sec.get("passed") is True:
        steps.append("security_revalidation: passed")
    elif sec:
        steps.append("security_revalidation: needs_review")
    else:
        steps.append("security_revalidation: pending")
    return steps
