"""
LLM 에이전트 (agent/llm_agent.py)

정적 분석 결과(VulnerabilityReport)를 받아서
LLM에 전달하고, 수정안(PatchSuggestion)을 반환합니다.

지원 프로바이더: openai, gemini, anthropic

사용법:
  from agent.llm_agent import DalloAgent

  agent = DalloAgent(api_key="...", model="gpt-4o", provider="openai")
  patches = agent.generate_patches(vulnerabilities)
"""

import os
import re
import sys
import time
import logging
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.schemas import VulnerabilityReport, PatchSuggestion, PatchStatus

logger = logging.getLogger(__name__)


# 프로바이더별 기본 모델
DEFAULT_MODELS = {
    "openai": "gpt-4o",
    "gemini": "gemini-1.5-flash",
    "anthropic": "claude-sonnet-4-20250514",
}

# 프로바이더별 환경변수 키
API_KEY_ENV = {
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}


class DalloAgent:
    """
    LLM 기반 코드 분석 및 리팩토링 에이전트

    3개 프로바이더(OpenAI, Gemini, Anthropic)를 지원하며,
    취약점 정보를 받아 수정 코드와 설명을 생성합니다.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_keys: Optional[list[str]] = None,
        model: Optional[str] = None,
        provider: str = "openai",
        max_retries: int = 2,
        temperature: float = 0.2,
    ):
        self.provider = provider.lower()
        if self.provider not in DEFAULT_MODELS:
            raise ValueError(f"지원하지 않는 프로바이더: {provider}. (openai/gemini/anthropic)")

        self.model = model or DEFAULT_MODELS[self.provider]
        self.max_retries = max_retries
        self.temperature = temperature

        # 멀티 API 키 지원 (로테이션)
        if api_keys:
            self._api_keys = [k for k in api_keys if k.strip()]
        elif api_key:
            self._api_keys = [api_key]
        else:
            env_val = os.environ.get(API_KEY_ENV[self.provider], "")
            # 쉼표로 여러 키를 설정할 수 있음: KEY1,KEY2
            self._api_keys = [k.strip() for k in env_val.split(",") if k.strip()]

        if not self._api_keys:
            raise ValueError(
                f"API 키가 필요합니다. {API_KEY_ENV[self.provider]} 환경변수를 설정하거나 "
                f"api_key/api_keys 파라미터를 전달하세요."
            )

        self._current_key_idx = 0
        self.api_key = self._api_keys[0]
        self._client = self._init_client()

        if len(self._api_keys) > 1:
            logger.info(f"API 키 {len(self._api_keys)}개 로드됨 (로테이션 활성화)")

    def _rotate_key(self):
        """다음 API 키로 전환합니다."""
        if len(self._api_keys) <= 1:
            return False
        self._current_key_idx = (self._current_key_idx + 1) % len(self._api_keys)
        self.api_key = self._api_keys[self._current_key_idx]
        self._client = self._init_client()
        logger.info(f"API 키 전환 → 키 #{self._current_key_idx + 1}")
        return True

    def _init_client(self):
        """프로바이더별 클라이언트 초기화"""
        if self.provider == "openai":
            from openai import OpenAI
            return OpenAI(api_key=self.api_key)

        elif self.provider == "gemini":
            from google import genai
            return genai.Client(api_key=self.api_key)

        elif self.provider == "anthropic":
            from anthropic import Anthropic
            return Anthropic(api_key=self.api_key)

    def generate_patch(self, vuln: VulnerabilityReport) -> PatchSuggestion:
        """
        취약점 1건에 대한 수정안을 생성합니다.

        Args:
            vuln: VulnerabilityReport 객체

        Returns:
            PatchSuggestion: 수정된 코드 + 설명
        """
        prompt = self._build_prompt(vuln)

        for attempt in range(self.max_retries + 1):
            try:
                response = self._call_llm(prompt)
                fixed_code, explanation = self._parse_response(response)

                if not fixed_code.strip():
                    raise ValueError("LLM이 빈 코드를 반환했습니다.")

                return PatchSuggestion(
                    vulnerability_id=vuln.id,
                    fixed_code=fixed_code,
                    explanation=explanation,
                    fix_type="recommended",
                    status=PatchStatus.GENERATED,
                )
            except Exception as e:
                err_str = str(e)
                logger.warning(f"[시도 {attempt+1}/{self.max_retries+1}] 수정안 생성 실패: {e}")

                # Rate limit 감지 시 키 전환 또는 대기
                if "429" in err_str or "quota" in err_str.lower():
                    if self._rotate_key():
                        logger.info(f"  Rate limit → 다른 API 키로 전환")
                    else:
                        wait = self._extract_retry_delay(err_str)
                        logger.info(f"  Rate limit 감지 — {wait}초 대기 중...")
                        time.sleep(wait)

                if attempt == self.max_retries:
                    return PatchSuggestion(
                        vulnerability_id=vuln.id,
                        fixed_code="",
                        explanation=f"수정안 생성 실패 ({self.max_retries+1}회 시도): {str(e)}",
                        status=PatchStatus.FAILED,
                    )

    @staticmethod
    def _extract_retry_delay(error_msg: str) -> int:
        """에러 메시지에서 retry delay 초를 추출합니다."""
        match = re.search(r"retry in (\d+)", error_msg, re.IGNORECASE)
        if match:
            return int(match.group(1)) + 2  # 여유 2초 추가
        return 30  # 기본 30초 대기

    def generate_patches(
        self,
        vulnerabilities: list[VulnerabilityReport],
    ) -> list[PatchSuggestion]:
        """여러 취약점에 대해 일괄 수정안 생성"""
        patches = []
        for i, vuln in enumerate(vulnerabilities):
            logger.info(f"[{i+1}/{len(vulnerabilities)}] {vuln.rule_id} ({vuln.severity}) 처리 중...")
            patch = self.generate_patch(vuln)
            patches.append(patch)
            logger.info(f"  → 상태: {patch.status}")
        return patches

    def _build_prompt(self, vuln: VulnerabilityReport) -> str:
        """취약점 정보를 기반으로 LLM 프롬프트를 구성합니다."""
        # 줄번호 접두사 제거 ("  13 | def..." → "def...")
        code = vuln.function_code or vuln.code_snippet
        cleaned_code = self._strip_line_numbers(code)
        imports = vuln.file_imports or "# (없음)"

        prompt = f"""당신은 보안 코드 리뷰 전문가입니다. 아래 보안 취약점을 분석하고 수정된 코드를 제공하세요.

## 취약점 정보
- 규칙: {vuln.rule_id} ({vuln.title})
- 심각도: {vuln.severity}
- 설명: {vuln.description}
- CWE: {vuln.cwe_id or 'N/A'}
- 파일: {vuln.file_path}:{vuln.line_number}

## Import 문
```python
{imports}
```

## 취약한 코드
```python
{cleaned_code}
```

## 요청사항
1. 위 취약점을 수정한 안전한 코드를 작성하세요.
2. 기존 기능(비즈니스 로직)은 유지하면서 보안만 강화하세요.
3. 수정 근거를 간단히 설명하세요.
4. 수정 코드는 바로 적용 가능해야 합니다.

## 응답 형식 (반드시 아래 형식을 지켜주세요)
### 수정된 코드
```python
(여기에 수정된 전체 함수 코드를 작성하세요. 줄번호 없이 순수 Python 코드만 작성하세요.)
```

### 수정 근거
(여기에 수정 이유를 설명하세요)
"""
        return prompt

    @staticmethod
    def _strip_line_numbers(code: str) -> str:
        """코드에서 줄번호 접두사를 제거합니다. (예: '  13 | def...' → 'def...')"""
        lines = code.split("\n")
        cleaned = []
        for line in lines:
            # "  13 | code" 또는 "13 | code" 패턴 감지
            match = re.match(r"^\s*\d+\s*\|\s?(.*)$", line)
            if match:
                cleaned.append(match.group(1))
            else:
                cleaned.append(line)
        return "\n".join(cleaned)

    def _call_llm(self, prompt: str) -> str:
        """프로바이더별 LLM API를 호출하고 텍스트 응답을 반환합니다."""
        if self.provider == "openai":
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "당신은 보안 코드 리뷰 전문가입니다. Python 보안 취약점을 분석하고 수정된 코드를 제공합니다."},
                    {"role": "user", "content": prompt},
                ],
                temperature=self.temperature,
                max_tokens=2048,
            )
            return response.choices[0].message.content

        elif self.provider == "gemini":
            from google.genai import types
            response = self._client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=self.temperature,
                    max_output_tokens=2048,
                ),
            )
            return response.text

        elif self.provider == "anthropic":
            response = self._client.messages.create(
                model=self.model,
                max_tokens=2048,
                temperature=self.temperature,
                system="당신은 보안 코드 리뷰 전문가입니다. Python 보안 취약점을 분석하고 수정된 코드를 제공합니다.",
                messages=[
                    {"role": "user", "content": prompt},
                ],
            )
            return response.content[0].text

    def _parse_response(self, response: str) -> tuple[str, str]:
        """
        LLM 응답에서 수정 코드와 설명을 추출합니다.

        Returns:
            (fixed_code, explanation) 튜플
        """
        fixed_code = ""
        explanation = ""

        # 전략 1: "수정된 코드" 헤더 뒤의 코드 블록
        header_code_pattern = r"(?:수정된\s*코드|Fixed\s*Code).*?\n```(?:python)?\s*\n(.*?)```"
        match = re.search(header_code_pattern, response, re.DOTALL | re.IGNORECASE)
        if match:
            fixed_code = match.group(1).strip()

        # 전략 2: 모든 python 코드 블록 중 마지막
        if not fixed_code:
            code_matches = re.findall(r"```python\s*\n(.*?)```", response, re.DOTALL)
            if code_matches:
                fixed_code = code_matches[-1].strip()

        # 전략 3: 언어 태그 없는 코드 블록
        if not fixed_code:
            code_matches = re.findall(r"```\s*\n(.*?)```", response, re.DOTALL)
            if code_matches:
                fixed_code = code_matches[-1].strip()

        # 설명 추출
        explanation_patterns = [
            r"###?\s*수정\s*근거\s*\n(.*?)(?:\n###|\n```|$)",
            r"수정\s*근거[:\s]*\n(.*?)(?:\n###|\n```|$)",
            r"###?\s*(?:설명|Explanation)\s*\n(.*?)(?:\n###|\n```|$)",
        ]
        for pattern in explanation_patterns:
            m = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
            if m:
                explanation = m.group(1).strip()
                break

        # 설명 폴백: 마지막 코드 블록 이후 텍스트
        if not explanation:
            last_code_end = response.rfind("```")
            if last_code_end != -1:
                remaining = response[last_code_end + 3:].strip()
                # 코드 블록 이전 텍스트도 확인
                if not remaining:
                    first_code_start = response.find("```")
                    if first_code_start > 0:
                        remaining = response[:first_code_start].strip()
                if remaining:
                    explanation = remaining

        if not explanation:
            explanation = "LLM이 수정 근거를 제공하지 않았습니다."

        return fixed_code, explanation


# CLI에서 직접 테스트할 수 있도록
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Dallo LLM Agent 테스트")
    parser.add_argument("--provider", default="openai", choices=["openai", "gemini", "anthropic"])
    parser.add_argument("--model", default=None)
    parser.add_argument("--api-key", default=None)
    args = parser.parse_args()

    # 테스트용 취약점 생성
    test_vuln = VulnerabilityReport(
        id="test_vuln_001",
        tool="bandit",
        rule_id="B608",
        severity="HIGH",
        confidence="HIGH",
        title="SQL Injection",
        description="Possible SQL injection via string-based query construction.",
        file_path="test_targets/sql_injection.py",
        line_number=10,
        code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
        function_code='''def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()''',
        file_imports="import sqlite3",
        cwe_id="CWE-89",
    )

    agent = DalloAgent(
        api_key=args.api_key,
        model=args.model,
        provider=args.provider,
    )

    print(f"프로바이더: {agent.provider}, 모델: {agent.model}")
    print("=" * 60)
    patch = agent.generate_patch(test_vuln)
    print(f"상태: {patch.status}")
    print(f"\n수정 코드:\n{patch.fixed_code}")
    print(f"\n설명:\n{patch.explanation}")
