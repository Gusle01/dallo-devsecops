"""
취약점 중복 제거 모듈 (analyzer/deduplicator.py)

동일 rule_id + 유사 코드 패턴을 가진 취약점을 그룹화합니다.
그룹 내 대표 취약점 1개만 LLM에 전달, 나머지는 "same-as" 참조로 관리합니다.
"""

import hashlib
import logging
from typing import Optional
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)


def _normalize_code(code: str) -> str:
    """코드를 정규화하여 비교 가능하게 만듭니다. (공백/줄번호 제거)"""
    lines = []
    for line in code.strip().split("\n"):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and not stripped.startswith("//"):
            lines.append(stripped)
    return "\n".join(lines)


def _code_similarity(code_a: str, code_b: str) -> float:
    """두 코드 스니펫의 유사도를 0~1 사이로 반환합니다."""
    norm_a = _normalize_code(code_a)
    norm_b = _normalize_code(code_b)
    if not norm_a or not norm_b:
        return 0.0
    return SequenceMatcher(None, norm_a, norm_b).ratio()


def _group_key(vuln) -> str:
    """그룹화 키 생성: rule_id + 코드 해시"""
    code = vuln.function_code or vuln.code_snippet or ""
    code_hash = hashlib.sha256(_normalize_code(code).encode()).hexdigest()[:12]
    return f"{vuln.rule_id}:{code_hash}"


class DeduplicationResult:
    """중복 제거 결과"""

    def __init__(self):
        self.representatives: list = []  # LLM에 전달할 대표 취약점
        self.duplicates: dict = {}       # {대표 ID: [중복 취약점 목록]}
        self.group_map: dict = {}        # {취약점 ID: 그룹 ID}

    @property
    def total_deduplicated(self) -> int:
        return sum(len(dups) for dups in self.duplicates.values())


def deduplicate(vulnerabilities: list, similarity_threshold: float = 0.85) -> DeduplicationResult:
    """
    취약점 목록에서 중복을 제거합니다.

    Args:
        vulnerabilities: VulnerabilityReport 리스트
        similarity_threshold: 코드 유사도 임계값 (0~1, 기본 0.85)

    Returns:
        DeduplicationResult: 대표 취약점 + 중복 매핑
    """
    result = DeduplicationResult()

    if not vulnerabilities:
        return result

    # 1차 그룹화: rule_id 기준
    rule_groups: dict[str, list] = {}
    for vuln in vulnerabilities:
        key = vuln.rule_id
        if key not in rule_groups:
            rule_groups[key] = []
        rule_groups[key].append(vuln)

    group_id = 0
    for rule_id, group in rule_groups.items():
        if len(group) == 1:
            # 단독 취약점 — 그대로 대표로 선정
            vuln = group[0]
            result.representatives.append(vuln)
            result.group_map[vuln.id] = f"grp_{group_id}"
            group_id += 1
            continue

        # 2차 그룹화: 코드 유사도 기반 클러스터링
        clusters: list[list] = []
        used = set()

        for i, vuln_a in enumerate(group):
            if i in used:
                continue

            cluster = [vuln_a]
            used.add(i)

            code_a = vuln_a.function_code or vuln_a.code_snippet or ""
            for j in range(i + 1, len(group)):
                if j in used:
                    continue
                vuln_b = group[j]
                code_b = vuln_b.function_code or vuln_b.code_snippet or ""

                if _code_similarity(code_a, code_b) >= similarity_threshold:
                    cluster.append(vuln_b)
                    used.add(j)

            clusters.append(cluster)

        # 클러스터별 대표 선정 (severity가 높은 것 우선)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for cluster in clusters:
            gid = f"grp_{group_id}"
            cluster.sort(key=lambda v: severity_order.get(v.severity.upper(), 99))
            representative = cluster[0]

            result.representatives.append(representative)
            result.group_map[representative.id] = gid

            if len(cluster) > 1:
                duplicates = cluster[1:]
                result.duplicates[representative.id] = duplicates
                for dup in duplicates:
                    result.group_map[dup.id] = gid

                logger.info(
                    f"[DEDUP] {rule_id}: {len(cluster)}개 → 대표 1개 (중복 {len(duplicates)}개 제거)"
                )

            group_id += 1

    total = len(vulnerabilities)
    deduped = len(result.representatives)
    logger.info(f"[DEDUP] 전체 {total}개 → 대표 {deduped}개 (중복 {total - deduped}개 제거)")

    return result
