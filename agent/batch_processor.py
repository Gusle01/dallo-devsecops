"""
LLM 배치 처리 모듈 (agent/batch_processor.py)

같은 파일 내 취약점들을 그룹핑하여 단일 프롬프트로 처리합니다.
최대 batch_size(기본 5)개 단위로 묶어 토큰 비용을 절감합니다.
"""

import logging
from typing import Optional

from shared.schemas import VulnerabilityReport, PatchSuggestion, PatchStatus

logger = logging.getLogger(__name__)


def group_by_file(vulnerabilities: list[VulnerabilityReport],
                  batch_size: int = 5) -> list[list[VulnerabilityReport]]:
    """
    취약점을 파일별로 그룹화하고, batch_size 단위로 분할합니다.

    Returns:
        [[vuln1, vuln2, ...], [vuln3, vuln4, ...], ...]
    """
    by_file: dict[str, list] = {}
    for vuln in vulnerabilities:
        fp = vuln.file_path
        if fp not in by_file:
            by_file[fp] = []
        by_file[fp].append(vuln)

    batches = []
    for file_path, vulns in by_file.items():
        # batch_size 단위로 분할
        for i in range(0, len(vulns), batch_size):
            batch = vulns[i:i + batch_size]
            batches.append(batch)

    logger.info(
        f"[BATCH] {len(vulnerabilities)}개 취약점 → "
        f"{len(batches)}개 배치 (파일 {len(by_file)}개)"
    )
    return batches


def build_batch_prompt(batch: list[VulnerabilityReport], lang: str = "Python") -> str:
    """배치 취약점에 대한 JSON 응답 프롬프트를 생성합니다."""
    from agent.prompts.gemini_refactor_prompt import build_batch_patch_prompt

    vuln_dicts = []
    for v in batch:
        vuln_dicts.append({
            "id": v.id,
            "rule_id": v.rule_id,
            "title": v.title,
            "severity": v.severity,
            "description": v.description,
            "code": v.function_code or v.code_snippet or "",
            "line_number": v.line_number,
        })

    return build_batch_patch_prompt(vuln_dicts, lang)


def parse_batch_response(response_text: str, batch: list[VulnerabilityReport]) -> list[PatchSuggestion]:
    """
    배치 LLM 응답(JSON)을 파싱하여 PatchSuggestion 리스트로 변환합니다.

    기대하는 응답 형식:
    {"patches": [{"vuln_id": "...", "fixed_code": "...", "explanation": "..."}, ...]}
    """
    import json
    import re

    patches = []

    # JSON 블록 추출
    json_match = re.search(r"```(?:json)?\s*\n(.*?)```", response_text, re.DOTALL)
    json_str = json_match.group(1) if json_match else response_text

    try:
        data = json.loads(json_str)
        items = data.get("patches", [])
    except (json.JSONDecodeError, AttributeError):
        logger.warning("[BATCH] JSON 파싱 실패 — 개별 처리로 fallback 필요")
        return patches

    vuln_map = {v.id: v for v in batch}

    for item in items:
        vuln_id = item.get("vuln_id", "")
        fixed_code = item.get("fixed_code", "").strip()
        explanation = item.get("explanation", "").strip()

        if fixed_code and vuln_id:
            patches.append(PatchSuggestion(
                vulnerability_id=vuln_id,
                fixed_code=fixed_code,
                explanation=explanation or "배치 처리 결과",
                fix_type="recommended",
                status=PatchStatus.GENERATED,
            ))

    logger.info(f"[BATCH] 응답에서 {len(patches)}/{len(batch)}개 패치 파싱 성공")
    return patches
