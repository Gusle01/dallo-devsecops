"""
캐싱 + 배치 처리 테스트 (tests/test_cache_batch.py)
"""

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.schemas import VulnerabilityReport, PatchSuggestion, PatchStatus
from agent.cache import LLMCache
from agent.batch_processor import group_by_file, parse_batch_response
from agent.response_parser import extract_json_from_response, extract_patches_from_json
from shared.llm_optimization import LLMOptimizationConfig, optimize_llm_targets
from agent.llm_agent import DalloAgent


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


class TestLLMOptimization:
    def test_cwe_scope_filters_targets(self):
        vulns = [
            _make_vuln("v1", rule_id="B608"),
            _make_vuln("v2", rule_id="B303"),
        ]
        vulns[0].cwe_id = "CWE-89"
        vulns[1].cwe_id = "CWE-328"

        selected, summary = optimize_llm_targets(
            vulns,
            LLMOptimizationConfig(cwe_scope=["CWE-89"], max_targets=10),
        )

        assert [v.id for v in selected] == ["v1"]
        assert summary["skipped_targets"] == 1

    def test_scope_alias_maps_to_cwe(self):
        vulns = [
            _make_vuln("v1", rule_id="HEUR-AUTH-BYPASS-USER-CONTROLLED-ID"),
            _make_vuln("v2", rule_id="B303"),
        ]
        vulns[0].cwe_id = "CWE-288"
        vulns[1].cwe_id = "CWE-328"

        selected, _ = optimize_llm_targets(
            vulns,
            LLMOptimizationConfig(cwe_scope=["AUTH-BYPASS"], max_targets=10),
        )

        assert [v.id for v in selected] == ["v1"]

    def test_context_is_trimmed(self):
        vuln = _make_vuln("v1")
        vuln.function_code = "a" * 5000

        selected, summary = optimize_llm_targets(
            [vuln],
            LLMOptimizationConfig(max_context_chars=1000),
        )

        assert len(selected[0].function_code) < 1200
        assert "context trimmed" in selected[0].function_code
        assert summary["max_context_chars"] == 1000


class DummyAuditProvider:
    model = "dummy"
    temperature = 0.2

    def call(self, prompt, system=None):
        return '{"status":"suspicious","summary":"Potential SSRF missed by static scan.","findings":[{"title":"SSRF","cwe_id":"CWE-918","severity":"HIGH","line_number":12,"evidence":"url","reason":"user input controls URL","recommendation":"allowlist host"}]}'


class TestCleanAudit:
    def test_audit_code_returns_structured_findings(self):
        agent = DalloAgent.__new__(DalloAgent)
        agent._provider = DummyAuditProvider()
        agent._cache = LLMCache(ttl=60)
        agent._cache._redis = None

        audit = agent.audit_code("String url = request.getParameter(\"url\");", "SSRFTask1.java", "java")

        assert audit["status"] == "suspicious"
        assert audit["findings"][0]["cwe_id"] == "CWE-918"
        assert audit["findings"][0]["line_number"] == 12

    def test_clean_audit_findings_generate_blue_team_patches(self):
        from analyzer import pipeline

        source = "String url = request.getParameter(\"url\");"
        audit = {
            "status": "suspicious",
            "summary": "Potential SSRF missed by static scan.",
            "findings": [{
                "title": "SSRF",
                "cwe_id": "CWE-918",
                "severity": "HIGH",
                "line_number": 12,
                "evidence": "url",
                "reason": "user input controls URL",
                "recommendation": "allowlist host",
            }],
        }
        generated_targets = []

        def fake_generate_patches(targets, *args, **kwargs):
            generated_targets.extend(targets)
            return [
                PatchSuggestion(
                    vulnerability_id=targets[0].id,
                    fixed_code="String url = allowedUrl(request);",
                    explanation="Allowlist the requested URL before use.",
                    status=PatchStatus.GENERATED,
                )
            ], None

        with (
            patch.object(pipeline, "_run_static_analysis", return_value=[]),
            patch.object(pipeline, "_generate_clean_audit", return_value=(audit, None)),
            patch.object(pipeline, "_generate_patches", side_effect=fake_generate_patches),
            patch.object(pipeline, "_validate_syntax", return_value=None),
            patch.object(pipeline, "_validate_security", return_value=None),
            patch.object(pipeline, "_persist_to_db", return_value=None),
        ):
            result = pipeline.execute_pipeline(
                job_id="job_clean_audit",
                code=source,
                filename="Gateway.java",
                use_llm=True,
                llm_audit_when_clean=True,
            )

        assert generated_targets
        assert generated_targets[0].id.startswith("llm_audit_")
        assert generated_targets[0].function_code == source
        assert len(result.result_data["patches"]) == 1
        assert result.result_data["red_blue_summary"]["blue_team"]["patches_generated"] == 1


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
