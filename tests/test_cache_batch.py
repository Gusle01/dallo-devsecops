"""
캐싱 + 배치 처리 테스트 (tests/test_cache_batch.py)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.schemas import VulnerabilityReport
from agent.cache import LLMCache
from agent.batch_processor import group_by_file, parse_batch_response
from agent.response_parser import extract_json_from_response, extract_patches_from_json


def _make_vuln(id, file_path="test.py", rule_id="B608"):
    return VulnerabilityReport(
        id=id, tool="bandit", rule_id=rule_id, severity="HIGH",
        confidence="HIGH", title="Test", description="test",
        file_path=file_path, line_number=1, code_snippet="code",
    )


class TestLLMCache:
    def test_memory_cache_set_get(self):
        cache = LLMCache(ttl=60)
        cache._redis = None  # 강제 메모리 모드
        cache.set("code", "B608", "ctx", {"fixed": "safe_code"})
        result = cache.get("code", "B608", "ctx")
        assert result == {"fixed": "safe_code"}

    def test_cache_miss(self):
        cache = LLMCache(ttl=60)
        cache._redis = None
        result = cache.get("nonexistent", "rule", "ctx")
        assert result is None

    def test_metrics(self):
        metrics = LLMCache.get_metrics()
        assert "hits" in metrics
        assert "misses" in metrics
        assert "hit_rate_pct" in metrics


class TestBatchProcessor:
    def test_group_by_file(self):
        vulns = [
            _make_vuln("v1", "a.py"),
            _make_vuln("v2", "a.py"),
            _make_vuln("v3", "b.py"),
        ]
        batches = group_by_file(vulns, batch_size=5)
        assert len(batches) == 2  # a.py 배치 + b.py 배치

    def test_batch_size_split(self):
        vulns = [_make_vuln(f"v{i}", "a.py") for i in range(8)]
        batches = group_by_file(vulns, batch_size=3)
        assert len(batches) == 3  # 3+3+2

    def test_parse_batch_response(self):
        vulns = [_make_vuln("v1"), _make_vuln("v2")]
        response = '''```json
{
  "patches": [
    {"vuln_id": "v1", "fixed_code": "safe_code_1", "explanation": "fix 1"},
    {"vuln_id": "v2", "fixed_code": "safe_code_2", "explanation": "fix 2"}
  ]
}
```'''
        patches = parse_batch_response(response, vulns)
        assert len(patches) == 2
        assert patches[0].fixed_code == "safe_code_1"


class TestResponseParser:
    def test_extract_json_from_code_block(self):
        text = 'Some text\n```json\n{"key": "value"}\n```\nMore text'
        result = extract_json_from_response(text)
        assert result == {"key": "value"}

    def test_extract_json_bare(self):
        text = '{"patches": [{"vuln_id": "v1", "fixed_code": "code"}]}'
        result = extract_json_from_response(text)
        assert "patches" in result

    def test_extract_patches(self):
        data = {"patches": [{"vuln_id": "v1"}, {"vuln_id": "v2"}]}
        patches = extract_patches_from_json(data)
        assert len(patches) == 2

    def test_invalid_json_returns_empty(self):
        result = extract_json_from_response("This is not JSON at all")
        assert result == {}
