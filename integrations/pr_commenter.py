"""
PR 코멘트 자동화 모듈

분석 결과를 마크다운 형태로 포맷팅하여
GitHub Pull Request에 코멘트로 게시합니다.
"""

from typing import Optional
from analyzer.bandit_runner import AnalysisResult, Vulnerability
from analyzer.context_extractor import CodeContext


# 심각도별 이모지 매핑
SEVERITY_EMOJI = {
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "🔵",
}

SEVERITY_LABEL = {
    "HIGH": "높음",
    "MEDIUM": "중간",
    "LOW": "낮음",
}


class PRCommenter:
    """PR 코멘트 포맷터"""

    def __init__(self, include_code_context: bool = True):
        self.include_code_context = include_code_context

    def format_summary_comment(
        self,
        result: AnalysisResult,
        contexts: Optional[list[CodeContext]] = None,
        llm_suggestions: Optional[list[dict]] = None,
    ) -> str:
        """
        분석 결과 전체를 하나의 PR 코멘트로 포맷팅합니다.

        Args:
            result: 분석 결과
            contexts: 코드 문맥 (선택)
            llm_suggestions: LLM 수정 제안 (선택, 향후 연동)

        Returns:
            마크다운 포맷의 코멘트 문자열
        """
        lines = []

        # 헤더
        lines.append("## 🔍 Dallo 보안 분석 결과")
        lines.append("")

        # 오류 발생 시
        if result.error:
            lines.append(f"> ⚠️ 분석 중 오류가 발생했습니다: `{result.error}`")
            return "\n".join(lines)

        # 취약점 없는 경우
        if result.total_issues == 0:
            lines.append("> ✅ **보안 취약점이 발견되지 않았습니다.** 깔끔한 코드입니다!")
            return "\n".join(lines)

        # 요약 테이블
        lines.append("### 📊 요약")
        lines.append("")
        lines.append(f"| 심각도 | 건수 |")
        lines.append(f"|--------|------|")
        lines.append(f"| 🔴 높음 (High) | **{result.high_count}** |")
        lines.append(f"| 🟡 중간 (Medium) | **{result.medium_count}** |")
        lines.append(f"| 🔵 낮음 (Low) | **{result.low_count}** |")
        lines.append(f"| **전체** | **{result.total_issues}** |")
        lines.append("")

        # 개별 취약점 상세
        lines.append("### 🛡️ 발견된 취약점")
        lines.append("")

        # 문맥 매핑 (있는 경우)
        context_map = {}
        if contexts:
            for ctx in contexts:
                key = (ctx.vulnerability.file_path, ctx.vulnerability.line_number)
                context_map[key] = ctx

        # LLM 제안 매핑 (있는 경우)
        suggestion_map = {}
        if llm_suggestions:
            for i, s in enumerate(llm_suggestions):
                suggestion_map[i] = s

        for idx, vuln in enumerate(result.vulnerabilities):
            emoji = SEVERITY_EMOJI.get(vuln.severity, "⚪")
            label = SEVERITY_LABEL.get(vuln.severity, "알 수 없음")

            lines.append(f"<details>")
            lines.append(f"<summary>{emoji} <b>[{vuln.rule_id}] {vuln.title}</b> — {vuln.file_path}:{vuln.line_number} (심각도: {label})</summary>")
            lines.append("")
            lines.append(f"**설명:** {vuln.description}")
            lines.append("")

            if vuln.cwe_id:
                lines.append(f"**CWE:** {vuln.cwe_id}")

            if vuln.more_info:
                lines.append(f"**참고:** [{vuln.rule_id} 상세 정보]({vuln.more_info})")

            lines.append("")

            # 취약 코드 스니펫
            if vuln.code_snippet:
                lines.append("**취약 코드:**")
                lines.append("```python")
                lines.append(vuln.code_snippet.strip())
                lines.append("```")
                lines.append("")

            # 코드 문맥 (있는 경우)
            key = (vuln.file_path, vuln.line_number)
            if self.include_code_context and key in context_map:
                ctx = context_map[key]
                if ctx.full_function:
                    lines.append("**함수 전체:**")
                    lines.append("```python")
                    lines.append(ctx.full_function)
                    lines.append("```")
                    lines.append("")

            # LLM 수정 제안 (있는 경우)
            if idx in suggestion_map:
                suggestion = suggestion_map[idx]
                lines.append("**🤖 AI 수정 제안:**")
                if suggestion.get("explanation"):
                    lines.append(f"> {suggestion['explanation']}")
                    lines.append("")
                if suggestion.get("fixed_code"):
                    lines.append("```python")
                    lines.append(suggestion["fixed_code"])
                    lines.append("```")
                    lines.append("")

            lines.append("</details>")
            lines.append("")

        # 풋터
        lines.append("---")
        lines.append(f"*🤖 Dallo DevSecOps — 정적 분석 도구: {result.tool}*")

        return "\n".join(lines)

    def format_inline_comment(self, vuln: Vulnerability) -> str:
        """PR의 특정 라인에 달릴 인라인 코멘트 포맷"""
        emoji = SEVERITY_EMOJI.get(vuln.severity, "⚪")
        label = SEVERITY_LABEL.get(vuln.severity, "알 수 없음")

        lines = [
            f"{emoji} **[{vuln.rule_id}] {vuln.title}** (심각도: {label})",
            "",
            vuln.description,
        ]

        if vuln.cwe_id:
            lines.append(f"\n📎 {vuln.cwe_id}")

        if vuln.more_info:
            lines.append(f"🔗 [상세 정보]({vuln.more_info})")

        return "\n".join(lines)
