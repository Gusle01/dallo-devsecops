"""
코드 문맥 추출 모듈

취약점 발생 위치를 기준으로 주변 코드를 추출하여
LLM이 코드 문맥을 이해할 수 있도록 구성합니다.
"""

import os
from dataclasses import dataclass
from typing import Optional

from analyzer.bandit_runner import Vulnerability


@dataclass
class CodeContext:
    """LLM에 전달할 코드 문맥"""
    vulnerability: Vulnerability
    full_function: str = ""           # 취약점이 포함된 함수 전체
    surrounding_code: str = ""        # 취약점 주변 코드 (±N줄)
    file_imports: str = ""            # 파일의 import 문
    file_path: str = ""
    start_line: int = 0
    end_line: int = 0
    total_lines: int = 0

    def to_prompt_context(self) -> str:
        """LLM 프롬프트에 삽입할 형태로 변환"""
        parts = []

        parts.append(f"## 취약점 정보")
        parts.append(f"- 규칙: {self.vulnerability.rule_id} ({self.vulnerability.title})")
        parts.append(f"- 심각도: {self.vulnerability.severity}")
        parts.append(f"- 설명: {self.vulnerability.description}")
        parts.append(f"- 파일: {self.vulnerability.file_path}")
        parts.append(f"- 라인: {self.vulnerability.line_number}")

        if self.vulnerability.cwe_id:
            parts.append(f"- CWE: {self.vulnerability.cwe_id}")

        if self.file_imports:
            parts.append(f"\n## Import 문")
            parts.append(f"```python\n{self.file_imports}\n```")

        if self.full_function:
            parts.append(f"\n## 취약점이 포함된 함수")
            parts.append(f"```python\n{self.full_function}\n```")
        elif self.surrounding_code:
            parts.append(f"\n## 취약점 주변 코드 (라인 {self.start_line}-{self.end_line})")
            parts.append(f"```python\n{self.surrounding_code}\n```")

        return "\n".join(parts)


class ContextExtractor:
    """취약점 주변 코드 문맥을 추출하는 클래스"""

    def __init__(self, context_lines: int = 10):
        """
        Args:
            context_lines: 취약점 위/아래로 추출할 줄 수
        """
        self.context_lines = context_lines

    def extract(self, vulnerability: Vulnerability) -> CodeContext:
        """
        취약점 정보를 기반으로 코드 문맥을 추출합니다.

        Args:
            vulnerability: 정규화된 취약점 정보

        Returns:
            CodeContext: 추출된 코드 문맥
        """
        ctx = CodeContext(
            vulnerability=vulnerability,
            file_path=vulnerability.file_path,
        )

        file_path = vulnerability.file_path
        if not os.path.exists(file_path):
            return ctx

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (IOError, UnicodeDecodeError):
            return ctx

        ctx.total_lines = len(lines)
        target_line = vulnerability.line_number  # 1-indexed

        # 1. import 문 추출
        ctx.file_imports = self._extract_imports(lines)

        # 2. 취약점이 포함된 함수 추출
        ctx.full_function = self._extract_function(lines, target_line)

        # 3. 주변 코드 추출 (함수를 못 찾은 경우 fallback)
        start = max(0, target_line - 1 - self.context_lines)
        end = min(len(lines), target_line + self.context_lines)
        ctx.start_line = start + 1
        ctx.end_line = end
        ctx.surrounding_code = self._numbered_lines(lines, start, end)

        return ctx

    def extract_batch(self, vulnerabilities: list[Vulnerability]) -> list[CodeContext]:
        """여러 취약점에 대해 일괄 문맥 추출"""
        return [self.extract(v) for v in vulnerabilities]

    def _extract_imports(self, lines: list[str]) -> str:
        """파일 상단의 import 문 추출"""
        imports = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("import ") or stripped.startswith("from "):
                imports.append(stripped)
            # 빈 줄이나 주석 이후 코드가 시작되면 import 영역 종료
            elif stripped and not stripped.startswith("#") and not stripped.startswith('"""') and not stripped.startswith("'''"):
                if imports:  # import가 이미 시작된 후에만 종료
                    break
        return "\n".join(imports)

    def _extract_function(self, lines: list[str], target_line: int) -> str:
        """취약점이 포함된 함수/메서드 전체를 추출"""
        target_idx = target_line - 1  # 0-indexed

        if target_idx >= len(lines) or target_idx < 0:
            return ""

        # 위로 올라가며 def/class 찾기
        func_start = None
        func_indent = None

        for i in range(target_idx, -1, -1):
            stripped = lines[i].lstrip()
            if stripped.startswith("def ") or stripped.startswith("async def "):
                func_start = i
                func_indent = len(lines[i]) - len(lines[i].lstrip())
                break

        if func_start is None:
            return ""

        # 아래로 내려가며 함수 끝 찾기
        func_end = func_start + 1
        for i in range(func_start + 1, len(lines)):
            line = lines[i]
            # 빈 줄은 건너뛰기
            if line.strip() == "":
                func_end = i + 1
                continue
            # 같은 또는 더 작은 들여쓰기의 코드를 만나면 함수 끝
            current_indent = len(line) - len(line.lstrip())
            if current_indent <= func_indent and line.strip():
                break
            func_end = i + 1

        return self._numbered_lines(lines, func_start, func_end)

    def _numbered_lines(self, lines: list[str], start: int, end: int) -> str:
        """줄 번호를 포함한 코드 문자열 생성"""
        numbered = []
        for i in range(start, end):
            line_num = i + 1
            line_content = lines[i].rstrip()
            numbered.append(f"{line_num:4d} | {line_content}")
        return "\n".join(numbered)
