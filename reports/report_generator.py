"""
분석 결과 리포트 생성기.

대시보드의 open_report 및 /api/report/generate 엔드포인트가 사용하는
간단한 Markdown/HTML 리포트를 생성합니다.
"""

from __future__ import annotations

import html
import os
from datetime import datetime


class ReportGenerator:
    def save_report(self, data: dict, output_dir: str = "reports", fmt: str = "both", include_deps: dict | None = None) -> dict:
        os.makedirs(output_dir, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        files = {}

        if fmt in {"md", "markdown", "both"}:
            md_path = os.path.join(output_dir, f"dallo_report_{stamp}.md")
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(self.generate_markdown(data, include_deps))
            files["markdown"] = md_path

        if fmt in {"html", "both"}:
            html_path = os.path.join(output_dir, f"dallo_report_{stamp}.html")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(self.generate_html(data, include_deps))
            files["html"] = html_path

        return files

    def generate_markdown(self, data: dict, deps_data: dict | None = None) -> str:
        summary = data.get("summary") or {}
        vulns = data.get("vulnerabilities") or []
        patches = data.get("patches") or []
        audit = data.get("llm_audit") or {}
        red_blue = data.get("red_blue_summary") or {}

        lines = [
            "# Dallo DevSecOps Security Report",
            "",
            f"- Session: `{data.get('session_id', '')}`",
            f"- Mode: `{data.get('analysis_mode', 'red_blue')}`",
            f"- Duration: `{data.get('duration_seconds', 0)}` seconds",
            "",
            "## Summary",
            "",
            f"- Total findings: {summary.get('total', len(vulns))}",
            f"- High: {summary.get('high', 0)}",
            f"- Medium: {summary.get('medium', 0)}",
            f"- Low: {summary.get('low', 0)}",
            f"- Patches generated: {summary.get('patches_generated', len(patches))}",
            "",
        ]

        if audit:
            lines.extend([
                "## LLM Clean Audit",
                "",
                f"- Status: `{audit.get('status', 'reviewed')}`",
                f"- Summary: {audit.get('summary', '')}",
                f"- Missed findings: {len(audit.get('findings') or [])}",
                "",
            ])

        lines.extend([
            "## Red Team / Blue Team",
            "",
            f"- Attack paths: {len(red_blue.get('attack_paths') or [])}",
            f"- Risk reduction: {(red_blue.get('comparison') or {}).get('risk_reduction_percent', 0)}%",
            "",
            "## Findings",
            "",
        ])

        if not vulns:
            lines.append("No findings.")
        for idx, vuln in enumerate(vulns, 1):
            lines.extend([
                f"### {idx}. {vuln.get('title', 'Untitled finding')}",
                "",
                f"- Severity: `{vuln.get('severity', 'LOW')}`",
                f"- Tool: `{vuln.get('tool', '')}`",
                f"- Rule: `{vuln.get('rule_id', '')}`",
                f"- CWE: `{vuln.get('cwe_id') or 'N/A'}`",
                f"- Location: `{vuln.get('file_path', '')}:{vuln.get('line_number', 0)}`",
                "",
                str(vuln.get("description") or ""),
                "",
            ])
            if vuln.get("code_snippet"):
                lines.extend(["```", str(vuln.get("code_snippet")), "```", ""])
            if vuln.get("attack_scenario"):
                lines.extend([f"Red Team: {vuln.get('attack_scenario')}", ""])
            if vuln.get("blue_team_strategy"):
                lines.extend([f"Blue Team: {vuln.get('blue_team_strategy')}", ""])

        if patches:
            lines.extend(["## Patches", ""])
            for patch in patches:
                lines.extend([
                    f"### Patch for `{patch.get('vulnerability_id', '')}`",
                    "",
                    f"- Status: `{patch.get('status', '')}`",
                    f"- Type: `{patch.get('fix_type', '')}`",
                    "",
                    str(patch.get("explanation") or ""),
                    "",
                ])
                if patch.get("fixed_code"):
                    lines.extend(["```", str(patch.get("fixed_code")), "```", ""])

        if deps_data:
            lines.extend(["## Dependency Scan", "", "Dependency scan data was included in this report.", ""])

        return "\n".join(lines)

    def generate_html(self, data: dict, deps_data: dict | None = None) -> str:
        md = self.generate_markdown(data, deps_data)
        body = self._markdownish_to_html(md)
        return f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dallo DevSecOps Security Report</title>
  <style>
    body {{ margin: 0; padding: 40px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0b0f14; color: #e8edf2; }}
    main {{ max-width: 980px; margin: 0 auto; }}
    h1, h2, h3 {{ color: #9eff7d; }}
    h1 {{ border-bottom: 2px solid #9eff7d; padding-bottom: 14px; }}
    h2 {{ margin-top: 34px; border-bottom: 1px solid #293241; padding-bottom: 8px; }}
    code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    code {{ color: #74d7ff; }}
    pre {{ background: #111821; border: 1px solid #293241; border-left: 3px solid #ffcf5a; padding: 14px; overflow-x: auto; white-space: pre-wrap; }}
    li {{ margin: 6px 0; }}
    p {{ line-height: 1.6; }}
  </style>
</head>
<body>
  <main>{body}</main>
</body>
</html>"""

    def _markdownish_to_html(self, markdown: str) -> str:
        parts = []
        in_code = False
        code_lines = []

        for raw in markdown.splitlines():
            line = raw.rstrip()
            if line == "```":
                if in_code:
                    parts.append(f"<pre>{html.escape(chr(10).join(code_lines))}</pre>")
                    code_lines = []
                    in_code = False
                else:
                    in_code = True
                continue

            if in_code:
                code_lines.append(line)
                continue

            if line.startswith("# "):
                parts.append(f"<h1>{html.escape(line[2:])}</h1>")
            elif line.startswith("## "):
                parts.append(f"<h2>{html.escape(line[3:])}</h2>")
            elif line.startswith("### "):
                parts.append(f"<h3>{html.escape(line[4:])}</h3>")
            elif line.startswith("- "):
                parts.append(f"<p>&bull; {self._inline_code(line[2:])}</p>")
            elif not line:
                parts.append("")
            else:
                parts.append(f"<p>{self._inline_code(line)}</p>")

        if in_code:
            parts.append(f"<pre>{html.escape(chr(10).join(code_lines))}</pre>")

        return "\n".join(parts)

    def _inline_code(self, text: str) -> str:
        escaped = html.escape(text)
        chunks = escaped.split("`")
        if len(chunks) == 1:
            return escaped
        result = []
        for idx, chunk in enumerate(chunks):
            result.append(f"<code>{chunk}</code>" if idx % 2 else chunk)
        return "".join(result)
