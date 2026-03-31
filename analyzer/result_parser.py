"""
분석 결과 파서 모듈

Bandit, SonarQube 등 다양한 정적 분석 도구의 결과를
공통 포맷으로 정규화합니다.
"""

import json
from typing import Optional
from analyzer.bandit_runner import Vulnerability, AnalysisResult


def load_bandit_report(report_path: str) -> AnalysisResult:
    """저장된 Bandit JSON 리포트를 로드하여 AnalysisResult로 변환"""
    result = AnalysisResult(tool="bandit", target_path="")

    try:
        with open(report_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        result.error = str(e)
        return result

    result.raw_output = raw
    results_list = raw.get("results", [])
    metrics = raw.get("metrics", {}).get("_totals", {})

    result.total_issues = len(results_list)
    result.high_count = metrics.get("SEVERITY.HIGH", 0)
    result.medium_count = metrics.get("SEVERITY.MEDIUM", 0)
    result.low_count = metrics.get("SEVERITY.LOW", 0)

    for item in results_list:
        cwe = item.get("issue_cwe", {})
        cwe_id = f"CWE-{cwe['id']}" if isinstance(cwe, dict) and cwe.get("id") else None

        vuln = Vulnerability(
            tool="bandit",
            rule_id=item.get("test_id", ""),
            severity=item.get("issue_severity", "UNDEFINED"),
            confidence=item.get("issue_confidence", "UNDEFINED"),
            title=item.get("test_name", ""),
            description=item.get("issue_text", ""),
            file_path=item.get("filename", ""),
            line_number=item.get("line_number", 0),
            col_offset=item.get("col_offset", 0),
            code_snippet=item.get("code", ""),
            cwe_id=cwe_id,
            more_info=item.get("more_info", ""),
        )
        result.vulnerabilities.append(vuln)

    return result


def merge_results(*results: AnalysisResult) -> AnalysisResult:
    """여러 도구의 분석 결과를 하나로 합침"""
    merged = AnalysisResult(
        tool="merged",
        target_path=results[0].target_path if results else "",
    )

    for r in results:
        merged.vulnerabilities.extend(r.vulnerabilities)
        merged.high_count += r.high_count
        merged.medium_count += r.medium_count
        merged.low_count += r.low_count

    merged.total_issues = len(merged.vulnerabilities)

    # 심각도 순 정렬: HIGH → MEDIUM → LOW
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    merged.vulnerabilities.sort(
        key=lambda v: severity_order.get(v.severity, 99)
    )

    return merged


def filter_by_severity(
    result: AnalysisResult,
    min_severity: str = "LOW"
) -> AnalysisResult:
    """특정 심각도 이상의 취약점만 필터링"""
    severity_levels = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    min_level = severity_levels.get(min_severity.upper(), 0)

    filtered = AnalysisResult(
        tool=result.tool,
        target_path=result.target_path,
    )

    for v in result.vulnerabilities:
        level = severity_levels.get(v.severity, 0)
        if level >= min_level:
            filtered.vulnerabilities.append(v)

    filtered.total_issues = len(filtered.vulnerabilities)
    filtered.high_count = sum(1 for v in filtered.vulnerabilities if v.severity == "HIGH")
    filtered.medium_count = sum(1 for v in filtered.vulnerabilities if v.severity == "MEDIUM")
    filtered.low_count = sum(1 for v in filtered.vulnerabilities if v.severity == "LOW")

    return filtered
