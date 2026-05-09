"""
Semgrep 정적 분석 모듈 (analyzer/semgrep_runner.py)

Bandit이 Python만 지원하는 반면, Semgrep은 30개+ 언어를 지원합니다.
Python, Java, JavaScript, TypeScript, Go, C/C++, Ruby, PHP 등

사용법:
    from analyzer.semgrep_runner import SemgrepRunner

    runner = SemgrepRunner()
    result = runner.run("path/to/code.java")
"""

import json
import subprocess
import os
from typing import Optional
import yaml

from analyzer.bandit_runner import Vulnerability, AnalysisResult


# 파일 확장자 → 언어 매핑
EXTENSION_MAP = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".rs": "rust",
    ".scala": "scala",
}

# Semgrep severity → 프로젝트 severity 매핑
SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


class SemgrepRunner:
    """Semgrep 정적 분석 도구 실행기 (다중 언어 지원)"""

    def __init__(self, config: str | list[str] | None = None):
        """
        Args:
            config: Semgrep 룰 설정
                    - "auto": Semgrep 자동 감지 룰
                    - "p/security-audit": 보안 감사 룰셋
                    - "p/owasp-top-ten": OWASP Top 10 룰셋
                    - list[str]: 여러 룰셋을 순차 실행 후 병합
        """
        self.configs = _normalize_configs(config)
        self.timeout = _load_semgrep_timeout()

    def detect_language(self, file_path: str) -> str:
        """파일 확장자로 언어를 감지합니다."""
        ext = os.path.splitext(file_path)[1].lower()
        return EXTENSION_MAP.get(ext, "unknown")

    def run(self, target_path: str, output_path: Optional[str] = None) -> AnalysisResult:
        """
        Semgrep 분석을 실행하고 결과를 반환합니다.

        Args:
            target_path: 분석할 파일 또는 디렉토리
            output_path: JSON 리포트 저장 경로 (선택)

        Returns:
            AnalysisResult: 정규화된 분석 결과
        """
        merged = AnalysisResult(tool="semgrep", target_path=target_path)
        errors = []

        for config in self.configs:
            result = self._run_one_config(target_path, config, output_path=None)
            if result.error:
                errors.append(f"{config}: {result.error}")
                continue
            merged.vulnerabilities.extend(result.vulnerabilities)
            merged.high_count += result.high_count
            merged.medium_count += result.medium_count
            merged.low_count += result.low_count

        merged.vulnerabilities = _dedupe_vulnerabilities(merged.vulnerabilities)
        _refresh_counts(merged)
        if errors and not merged.vulnerabilities:
            merged.error = "; ".join(errors)[:500]
        elif errors:
            merged.raw_output = {"partial_errors": errors}

        if output_path:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(merged.to_dict(), f, indent=2, ensure_ascii=False)

        return merged

    def _run_one_config(self, target_path: str, config: str, output_path: Optional[str] = None) -> AnalysisResult:
        result = AnalysisResult(tool="semgrep", target_path=target_path)

        cmd = [
            "semgrep",
            "--config", config,
            "--json",
            "--quiet",
            target_path,
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            output = proc.stdout
            if not output:
                # Semgrep이 결과를 stderr에 쓰는 경우도 있음
                if proc.returncode == 0:
                    result.total_issues = 0
                    return result
                result.error = proc.stderr.strip()[:500] if proc.stderr else "Semgrep 실행 실패"
                return result

            raw = json.loads(output)
            result.raw_output = raw

            if output_path:
                os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(raw, f, indent=2, ensure_ascii=False)

            result = self._parse_results(raw, result)

        except subprocess.TimeoutExpired:
            result.error = f"Semgrep 분석 시간 초과 ({self.timeout}초)"
        except json.JSONDecodeError as e:
            result.error = f"Semgrep 출력 JSON 파싱 실패: {e}"
        except FileNotFoundError:
            result.error = "Semgrep이 설치되어 있지 않습니다. pip install semgrep"

        return result

    def _parse_results(self, raw: dict, result: AnalysisResult) -> AnalysisResult:
        """Semgrep JSON 출력을 정규화된 형태로 변환"""
        findings = raw.get("results", [])

        result.total_issues = len(findings)

        for item in findings:
            severity_raw = item.get("extra", {}).get("severity", "WARNING")
            severity = SEVERITY_MAP.get(severity_raw, "MEDIUM")

            if severity == "HIGH":
                result.high_count += 1
            elif severity == "MEDIUM":
                result.medium_count += 1
            else:
                result.low_count += 1

            # CWE 추출
            metadata = item.get("extra", {}).get("metadata", {})
            cwe_list = metadata.get("cwe", [])
            cwe_id = None
            if cwe_list:
                cwe_val = cwe_list[0] if isinstance(cwe_list, list) else cwe_list
                if isinstance(cwe_val, str) and "CWE-" in cwe_val:
                    cwe_id = cwe_val.split(":")[0].strip()

            # 코드 스니펫 — Semgrep lines가 짧으면 파일에서 주변 코드 가져오기
            lines = item.get("extra", {}).get("lines", "")
            start_line = item.get("start", {}).get("line", 0)
            end_line_num = item.get("end", {}).get("line", start_line)
            if len(lines.strip()) < 20 and start_line > 0:
                try:
                    file_path = item.get("path", "")
                    with open(file_path, "r", encoding="utf-8") as f:
                        all_lines = f.readlines()
                    ctx_start = max(0, start_line - 3)
                    ctx_end = min(len(all_lines), end_line_num + 2)
                    lines = "".join(all_lines[ctx_start:ctx_end])
                except Exception:
                    pass

            vuln = Vulnerability(
                tool="semgrep",
                rule_id=item.get("check_id", "").split(".")[-1],  # 마지막 부분만
                severity=severity,
                confidence="HIGH",
                title=item.get("check_id", "").split(".")[-1],
                description=item.get("extra", {}).get("message", ""),
                file_path=item.get("path", ""),
                line_number=item.get("start", {}).get("line", 0),
                end_line=item.get("end", {}).get("line"),
                code_snippet=lines,
                cwe_id=cwe_id,
                more_info=metadata.get("source", ""),
            )
            result.vulnerabilities.append(vuln)

        return result


def detect_and_run(target_path: str) -> AnalysisResult:
    """파일 확장자를 감지하고 적절한 분석기를 실행합니다."""
    ext = os.path.splitext(target_path)[1].lower()
    from analyzer.heuristic_runner import HeuristicRunner
    from analyzer.result_parser import merge_results

    heuristic_result = HeuristicRunner().run(target_path)

    if ext == ".py":
        # Python: Bandit + Semgrep 병합
        from analyzer.bandit_runner import BanditRunner

        bandit = BanditRunner()
        bandit_result = bandit.run(target_path)

        semgrep = SemgrepRunner()
        semgrep_result = semgrep.run(target_path)

        return merge_results(bandit_result, semgrep_result, heuristic_result)

    elif ext in EXTENSION_MAP:
        # 기타 언어: Semgrep + 로컬 휴리스틱 fallback
        runner = SemgrepRunner()
        semgrep_result = runner.run(target_path)
        return merge_results(semgrep_result, heuristic_result)

    else:
        return AnalysisResult(
            tool="none",
            target_path=target_path,
            error=f"지원하지 않는 파일 형식: {ext}",
        )


def _normalize_configs(config: str | list[str] | None) -> list[str]:
    if config is None:
        return _load_semgrep_configs()
    if isinstance(config, str):
        return [config]
    return [str(c) for c in config if str(c).strip()]


def _load_semgrep_configs() -> list[str]:
    cfg = _load_project_config().get("semgrep", {})
    configs = cfg.get("configs") or ["auto"]
    return [str(c) for c in configs if str(c).strip()]


def _load_semgrep_timeout() -> int:
    cfg = _load_project_config().get("semgrep", {})
    return int(cfg.get("timeout_seconds", 120))


def _load_project_config() -> dict:
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "config.yaml")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _dedupe_vulnerabilities(vulns: list[Vulnerability]) -> list[Vulnerability]:
    seen = set()
    result = []
    for v in vulns:
        key = (v.rule_id, v.file_path, v.line_number, (v.code_snippet or "").strip()[:120])
        if key in seen:
            continue
        seen.add(key)
        result.append(v)
    return result


def _refresh_counts(result: AnalysisResult):
    result.total_issues = len(result.vulnerabilities)
    result.high_count = sum(1 for v in result.vulnerabilities if v.severity == "HIGH")
    result.medium_count = sum(1 for v in result.vulnerabilities if v.severity == "MEDIUM")
    result.low_count = sum(1 for v in result.vulnerabilities if v.severity == "LOW")
