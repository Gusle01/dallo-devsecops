"""LLM 응답 파서 테스트 (API 호출 없이 파싱 로직만 테스트)"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.llm_agent import DalloAgent


class TestLLMParser:
    """_parse_response, _strip_line_numbers 테스트"""

    def test_parse_standard_response(self):
        """표준 형식 응답 파싱"""
        response = """### 수정된 코드
```python
def safe_query(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
```

### 수정 근거
파라미터화된 쿼리를 사용하여 SQL 인젝션을 방지합니다.
"""
        code, explanation = DalloAgent._parse_response(None, response)
        assert "SELECT * FROM users WHERE id = ?" in code
        assert "파라미터" in explanation

    def test_parse_no_header_response(self):
        """헤더 없이 코드 블록만 있는 응답"""
        response = """수정된 코드입니다:

```python
import subprocess

def safe_run(cmd):
    subprocess.run(cmd, shell=False)
```

shell=False로 변경하여 명령어 삽입을 방지합니다.
"""
        code, explanation = DalloAgent._parse_response(None, response)
        assert "shell=False" in code
        assert explanation  # 뭔가 설명이 있어야 함

    def test_parse_multiple_code_blocks(self):
        """코드 블록이 여러 개인 경우 마지막 것을 사용"""
        response = """기존 코드:
```python
import hashlib
hashlib.md5(data)
```

수정된 코드:
```python
import hashlib
hashlib.sha256(data)
```

### 수정 근거
MD5 대신 SHA-256을 사용합니다.
"""
        code, explanation = DalloAgent._parse_response(None, response)
        assert "sha256" in code
        assert "MD5" in explanation or "SHA" in explanation

    def test_parse_empty_response(self):
        """빈 응답"""
        code, explanation = DalloAgent._parse_response(None, "")
        assert code == ""

    def test_parse_no_code_block(self):
        """코드 블록이 없는 응답"""
        response = "이 취약점을 수정하려면 파라미터화된 쿼리를 사용하세요."
        code, explanation = DalloAgent._parse_response(None, response)
        assert code == ""

    def test_strip_line_numbers(self):
        """줄번호 제거"""
        code = """  13 | def ping_host(hostname: str) -> str:
  14 |     os.system(f"ping -c 3 {hostname}")
  15 |     return f"Ping to {hostname} completed"
"""
        result = DalloAgent._strip_line_numbers(code)
        assert "13 |" not in result
        assert "def ping_host" in result

    def test_strip_line_numbers_no_numbers(self):
        """줄번호 없는 코드는 그대로 통과"""
        code = "def hello():\n    return 'world'"
        result = DalloAgent._strip_line_numbers(code)
        assert result == code

    def test_parse_explanation_before_code(self):
        """설명이 코드 앞에 나오는 경우"""
        response = """이 취약점은 위험합니다. 아래와 같이 수정하세요.

### 수정된 코드
```python
def safe():
    pass
```

### 수정 근거
안전한 패턴으로 변경했습니다.
"""
        code, explanation = DalloAgent._parse_response(None, response)
        assert "def safe" in code
        assert "안전" in explanation
