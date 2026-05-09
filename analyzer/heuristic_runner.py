"""
휴리스틱 정적 분석 모듈.

Semgrep 같은 외부 분석기가 없거나 룰셋이 특정 패턴을 놓칠 때,
대시보드의 빠른 스캔과 full scan 결과가 크게 어긋나지 않도록
대표적인 취약 패턴을 로컬 정규식으로 보완합니다.
"""

import os
import re

from analyzer.bandit_runner import AnalysisResult, Vulnerability


class HeuristicRunner:
    """언어별 기본 보안 패턴을 검사하는 fallback 분석기."""

    SQL_KEYWORDS = r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)"

    RULES = [
        {
            "rule_id": "HEUR-SQL-INJECT",
            "title": "SQL Injection 가능성",
            "severity": "HIGH",
            "cwe_id": "CWE-89",
            "message": "사용자 입력이 SQL 쿼리에 직접 결합될 수 있습니다. 파라미터 바인딩을 사용하세요.",
            "patterns": [
                rf'f"[^"]*{SQL_KEYWORDS}\b[^"]*\{{',
                rf"f'[^']*{SQL_KEYWORDS}\b[^']*\{{",
                rf'["\'].*{SQL_KEYWORDS}\b.*["\']\s*\+',
                r"(?:executeQuery|executeUpdate|execute)\([^)]*\+",
            ],
        },
        {
            "rule_id": "HEUR-CMD-INJECT",
            "title": "Command Injection 가능성",
            "severity": "HIGH",
            "cwe_id": "CWE-78",
            "message": "외부 명령어에 사용자 입력이 직접 결합될 수 있습니다. 허용 목록이나 안전한 인자 배열을 사용하세요.",
            "patterns": [
                r"os\.system\s*\(\s*f[\"']",
                r"os\.system\s*\([^)]*\+",
                r"subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True",
                r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+",
                r"child_process.*exec\s*\([^)]*\+",
            ],
        },
        {
            "rule_id": "HEUR-HARDCODED-SECRET",
            "title": "하드코딩된 인증 정보",
            "severity": "HIGH",
            "cwe_id": "CWE-798",
            "message": "인증 정보가 소스코드에 하드코딩되어 있습니다. 환경변수나 시크릿 매니저를 사용하세요.",
            "patterns": [
                r"(?:API_KEY|API_SECRET|SECRET_KEY|ACCESS_KEY|PRIVATE_KEY)\s*=\s*[\"'][^\"']{8,}[\"']",
                r"(?:password|passwd|pwd)\s*=\s*[\"'][^\"']{4,}[\"']",
                r"(?:token|TOKEN)\s*=\s*[\"'][^\"']{8,}[\"']",
            ],
        },
        {
            "rule_id": "HEUR-WEAK-HASH",
            "title": "취약한 해시 알고리즘",
            "severity": "MEDIUM",
            "cwe_id": "CWE-328",
            "message": "MD5/SHA1은 보안 용도에 부적합합니다. SHA-256 이상 또는 bcrypt/argon2를 사용하세요.",
            "patterns": [
                r"hashlib\.(?:md5|sha1)\s*\(",
                r"MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-1|SHA1)[\"']",
                r"crypto\.create(?:Hash|Hmac)\s*\(\s*[\"'](?:md5|sha1)[\"']",
            ],
        },
        {
            "rule_id": "HEUR-AUTH-BYPASS-USER-CONTROLLED-ID",
            "title": "사용자 제어 계정 ID 기반 인증 우회 가능성",
            "severity": "HIGH",
            "cwe_id": "CWE-288",
            "message": "인증/계정 검증 엔드포인트가 요청 파라미터의 userId를 신뢰해 세션 검증 상태를 설정할 수 있습니다. 인증된 사용자 컨텍스트와 서버 측 계정 소유권 검증을 사용하세요.",
            "patterns": [
                r"@RequestParam\s+String\s+userId",
                r"setValue\s*\(\s*[\"']account-verified-id[\"']\s*,\s*userId\s*\)",
                r"verifyAccount\s*\(\s*Integer\.valueOf\s*\(\s*userId\s*\)",
            ],
        },
    ]

    def run(self, target_path: str) -> AnalysisResult:
        result = AnalysisResult(tool="heuristic", target_path=target_path)

        if os.path.isdir(target_path):
            paths = []
            for root, dirs, files in os.walk(target_path):
                dirs[:] = [d for d in dirs if d not in {"node_modules", "dist", "build", ".git", "venv", ".venv"}]
                for name in files:
                    paths.append(os.path.join(root, name))
        else:
            paths = [target_path]

        for path in paths:
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    code = f.read()
            except UnicodeDecodeError:
                continue

            result.vulnerabilities.extend(self._scan_code(code, path))

        self._refresh_counts(result)
        return result

    def _scan_code(self, code: str, file_path: str) -> list[Vulnerability]:
        findings = []
        lines = code.splitlines()
        seen = set()

        for rule in self.RULES:
            if rule["rule_id"] == "HEUR-AUTH-BYPASS-USER-CONTROLLED-ID":
                auth_finding = self._scan_auth_bypass_rule(code, file_path, lines, rule)
                if auth_finding:
                    findings.append(auth_finding)
                continue

            for pattern in rule["patterns"]:
                regex = re.compile(pattern, re.IGNORECASE)
                for line_num, line_text in enumerate(lines, 1):
                    if not regex.search(line_text):
                        continue
                    key = (rule["rule_id"], file_path, line_num)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(Vulnerability(
                        tool="heuristic",
                        rule_id=rule["rule_id"],
                        severity=rule["severity"],
                        confidence="MEDIUM",
                        title=rule["title"],
                        description=rule["message"],
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line_text.strip(),
                        cwe_id=rule["cwe_id"],
                    ))

        return findings

    @staticmethod
    def _scan_auth_bypass_rule(code: str, file_path: str, lines: list[str], rule: dict) -> Vulnerability | None:
        """Detect account verification flows that trust request-controlled userId."""
        required_hits = [
            re.search(r"@RequestParam\s+String\s+userId", code),
            re.search(r"verifyAccount\s*\(\s*Integer\.valueOf\s*\(\s*userId\s*\)", code),
            re.search(r"setValue\s*\(\s*[\"']account-verified-id[\"']\s*,\s*userId\s*\)", code),
        ]
        if not all(required_hits):
            return None

        line_number = 1
        for i, line in enumerate(lines, 1):
            if "setValue" in line and "account-verified-id" in line:
                line_number = i
                break

        snippet_start = max(0, line_number - 8)
        snippet_end = min(len(lines), line_number + 4)
        snippet = "\n".join(lines[snippet_start:snippet_end]).strip()

        return Vulnerability(
            tool="heuristic",
            rule_id=rule["rule_id"],
            severity=rule["severity"],
            confidence="MEDIUM",
            title=rule["title"],
            description=rule["message"],
            file_path=file_path,
            line_number=line_number,
            code_snippet=snippet,
            cwe_id=rule["cwe_id"],
        )

    @staticmethod
    def _refresh_counts(result: AnalysisResult):
        result.total_issues = len(result.vulnerabilities)
        result.high_count = sum(1 for v in result.vulnerabilities if v.severity == "HIGH")
        result.medium_count = sum(1 for v in result.vulnerabilities if v.severity == "MEDIUM")
        result.low_count = sum(1 for v in result.vulnerabilities if v.severity == "LOW")
