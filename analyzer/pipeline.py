"""
분석 파이프라인 (analyzer/pipeline.py)

정적 분석 → 문맥 추출 → 중복 제거 → 위험도 산정 → LLM → 검증 → 보안 재검증
전체 흐름을 단일 모듈로 통합합니다.

api/server.py와 api/tasks.py 양쪽에서 이 모듈을 호출하여 중복을 제거합니다.
"""

import os
import tempfile
import shutil
import time
import logging
import yaml
from datetime import datetime
from typing import Optional, Callable

logger = logging.getLogger(__name__)

# 입력 크기 제한
MAX_CODE_SIZE = 1_000_000  # 1MB


class PipelineResult:
    """파이프라인 실행 결과"""

    def __init__(self):
        self.result_data: dict = {}
        self.language: str = "unknown"
        self.llm_error: Optional[str] = None
        self.db_error: Optional[str] = None


def execute_pipeline(
    job_id: str,
    code: str,
    filename: str,
    use_llm: bool = True,
    provider: str = "gateway",
    model: str = "claude-sonnet-4-6",
    multi_patch: bool = False,
    cve_scope: Optional[list[str]] = None,
    cwe_scope: Optional[list[str]] = None,
    rule_scope: Optional[list[str]] = None,
    max_llm_targets: Optional[int] = None,
    max_context_chars: Optional[int] = None,
    batch_llm: Optional[bool] = None,
    llm_audit_when_clean: bool = False,
    on_progress: Optional[Callable[[str], None]] = None,
) -> PipelineResult:
    """
    분석 파이프라인을 실행합니다.

    Args:
        job_id: 작업 고유 ID
        code: 분석 대상 코드 문자열
        filename: 파일명 (언어 감지에 사용)
        use_llm: LLM 수정안 생성 여부
        provider: LLM 프로바이더
        model: LLM 모델명
        multi_patch: 다중 수정안 생성 여부
        on_progress: 진행 상황 콜백 (단계 메시지 문자열 전달)

    Returns:
        PipelineResult

    Raises:
        ValueError: 코드 크기 초과
        Exception: 분석 실패
    """
    def _progress(msg: str):
        if on_progress:
            on_progress(msg)

    if len(code) > MAX_CODE_SIZE:
        raise ValueError("코드가 너무 큽니다 (최대 1MB)")

    start_time = time.time()
    pipeline_result = PipelineResult()
    tmp_dir = tempfile.mkdtemp(prefix="dallo_analyze_")

    try:
        # 임시 파일 생성
        file_path = os.path.join(tmp_dir, filename)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(code)

        lang = _detect_language(filename)
        pipeline_result.language = lang

        # Step 1: 정적 분석
        _progress(f"정적 분석 중... ({lang})")
        vuln_reports = _run_static_analysis(file_path, filename, lang)

        # Step 2: 문맥 추출
        _progress("코드 문맥 추출 중...")
        vuln_reports = _extract_context(vuln_reports, filename)

        # Step 3: 중복 제거
        _progress("중복 취약점 제거 중...")
        llm_targets = _deduplicate(vuln_reports)

        # Step 4: 위험도 산정
        _progress("위험도 산정 중...")
        _score_risk(vuln_reports)

        # Step 5: LLM 대상 최적화 + 수정안 생성
        patches = []
        optimization_summary = {}
        llm_audit = None
        if use_llm and llm_targets:
            _progress("LLM 대상 범위 최적화 중...")
            opt_config = _build_optimization_config(
                cve_scope=cve_scope,
                cwe_scope=cwe_scope,
                rule_scope=rule_scope,
                max_llm_targets=max_llm_targets,
                max_context_chars=max_context_chars,
                batch_llm=batch_llm,
            )
            llm_targets, optimization_summary = _optimize_llm_targets(llm_targets, opt_config)
            _progress(
                f"AI 수정안 생성 중... ({len(llm_targets)}/{len(vuln_reports)}건, "
                f"batch={'on' if opt_config.batch_enabled and not multi_patch else 'off'})"
            )
            patches, llm_error = _generate_patches(llm_targets, provider, model, multi_patch, opt_config)
            pipeline_result.llm_error = llm_error
        elif use_llm and llm_audit_when_clean:
            _progress("AI 클린 스캔 재검토 중...")
            llm_audit, llm_error = _generate_clean_audit(
                code=code,
                filename=filename,
                lang=lang,
                provider=provider,
                model=model,
                max_context_chars=max_context_chars,
            )
            pipeline_result.llm_error = llm_error
            if llm_audit:
                audit_vulns = _audit_findings_to_vulnerabilities(llm_audit, filename, lang)
                if audit_vulns:
                    vuln_reports.extend(audit_vulns)
                    _score_risk(audit_vulns)

        # Step 6: 코드 검증
        if patches:
            _progress("코드 검증 중...")
            _validate_syntax(patches, lang)

        # Step 7: 보안 재검증
        if patches:
            _progress("보안 재검증 중...")
            _validate_security(patches, vuln_reports, lang, filename)

        # 결과 조립
        _progress("결과 저장 중...")
        elapsed = time.time() - start_time
        result_data = _build_result(job_id, vuln_reports, patches, elapsed)
        result_data["llm_optimization"] = optimization_summary
        if llm_audit:
            result_data["llm_audit"] = llm_audit
        if pipeline_result.llm_error:
            result_data["llm_error"] = pipeline_result.llm_error

        # DB 저장
        db_error = _persist_to_db(result_data)
        pipeline_result.db_error = db_error
        pipeline_result.result_data = result_data

        _progress("완료")
        return pipeline_result

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ============================================================
# 파이프라인 단계별 private 함수
# ============================================================

def _detect_language(filename: str) -> str:
    """파일 확장자에서 언어를 감지합니다."""
    from analyzer.semgrep_runner import EXTENSION_MAP
    ext = os.path.splitext(filename)[1].lower()
    return EXTENSION_MAP.get(ext, "unknown")


def _run_static_analysis(file_path: str, filename: str, lang: str) -> list:
    """정적 분석을 실행하고 raw 취약점 목록을 반환합니다."""
    from analyzer.semgrep_runner import detect_and_run
    from shared.schemas import VulnerabilityReport

    result = detect_and_run(file_path)

    vuln_reports = []
    for vuln in result.vulnerabilities:
        vuln_reports.append(VulnerabilityReport(
            id=f"vuln_{vuln.rule_id}_{vuln.line_number}",
            tool=vuln.tool,
            rule_id=vuln.rule_id,
            severity=vuln.severity,
            confidence=vuln.confidence,
            title=vuln.title,
            description=vuln.description,
            file_path=filename,
            line_number=vuln.line_number,
            code_snippet=vuln.code_snippet,
            cwe_id=vuln.cwe_id,
        ))
    return vuln_reports


def _extract_context(vuln_reports: list, filename: str) -> list:
    """취약점 주변 코드 문맥을 추출하여 vuln_reports에 반영합니다."""
    from analyzer.context_extractor import ContextExtractor

    extractor = ContextExtractor(context_lines=10)
    # context_extractor는 원래 분석기 결과 객체를 받으므로,
    # VulnerabilityReport에 대해서는 file_path 기반으로 추출 시도
    try:
        contexts = extractor.extract_batch(vuln_reports)
        context_map = {}
        for ctx in contexts:
            key = (ctx.vulnerability.file_path, ctx.vulnerability.line_number)
            context_map[key] = ctx

        for vuln in vuln_reports:
            ctx = context_map.get((vuln.file_path, vuln.line_number))
            if ctx:
                vuln.function_code = ctx.full_function
                vuln.file_imports = ctx.file_imports
    except Exception:
        # 문맥 추출 실패는 치명적이지 않음 — 코드 스니펫으로 진행
        logger.warning("[PIPELINE] 문맥 추출 실패 — 코드 스니펫으로 진행")

    return vuln_reports


def _deduplicate(vuln_reports: list) -> list:
    """중복 취약점을 제거하고 LLM 전달 대상(대표)을 반환합니다."""
    from analyzer.deduplicator import deduplicate

    dedup_result = deduplicate(vuln_reports)
    for vuln in vuln_reports:
        vuln.duplicate_group_id = dedup_result.group_map.get(vuln.id, "")
    return dedup_result.representatives


def _score_risk(vuln_reports: list):
    """전체 취약점에 위험도를 산정합니다."""
    from analyzer.risk_scorer import score_vulnerabilities
    score_vulnerabilities(vuln_reports)
    _apply_red_team_context(vuln_reports)


def _apply_red_team_context(vuln_reports: list):
    """Red Team 관점의 공격 시나리오와 Blue Team 방어 방향을 보강합니다."""
    from shared.red_blue import enrich_vulnerability

    for vuln in vuln_reports:
        enriched = enrich_vulnerability(vuln.to_dict())
        vuln.red_team_phase = enriched.get("red_team_phase", "")
        vuln.attack_vector = enriched.get("attack_vector", "")
        vuln.attack_scenario = enriched.get("attack_scenario", "")
        vuln.exploitability = enriched.get("exploitability", "")
        vuln.security_impact = enriched.get("security_impact", "")
        vuln.blue_team_strategy = enriched.get("blue_team_strategy", "")
        vuln.attack_plan = enriched.get("attack_plan", {})


def _generate_patches(
    llm_targets: list, provider: str, model: str, multi_patch: bool, opt_config=None
) -> tuple[list, str | None]:
    """LLM 수정안을 생성합니다. (에러 시 빈 리스트 + 에러 메시지 반환)"""
    try:
        from agent.llm_agent import DalloAgent
        agent = DalloAgent(provider=provider, model=model)
        patches = agent.generate_patches(
            llm_targets,
            multi=multi_patch,
            batch=bool(opt_config and opt_config.batch_enabled and not multi_patch),
            batch_size=(opt_config.batch_size if opt_config else 5),
        )
        return patches, None
    except Exception as e:
        logger.warning(f"[PIPELINE] LLM 수정안 생성 실패: {e}")
        return [], str(e)


def _generate_clean_audit(
    code: str,
    filename: str,
    lang: str,
    provider: str,
    model: str,
    max_context_chars: Optional[int] = None,
) -> tuple[dict | None, str | None]:
    """취약점 0건일 때 LLM 보안 재검토를 실행합니다."""
    try:
        from agent.llm_agent import DalloAgent
        agent = DalloAgent(provider=provider, model=model)
        audit = agent.audit_code(
            code=code,
            filename=filename,
            language=lang,
            max_chars=int(max_context_chars or 4000),
        )
        return audit, None
    except Exception as e:
        logger.warning(f"[PIPELINE] LLM 클린 스캔 재검토 실패: {e}")
        return None, str(e)


def _audit_findings_to_vulnerabilities(audit: dict, filename: str, lang: str) -> list:
    """LLM clean audit findings를 대시보드/리포트용 취약점으로 승격합니다."""
    from shared.schemas import VulnerabilityReport

    findings = audit.get("findings", []) if isinstance(audit, dict) else []
    vulns = []
    for idx, finding in enumerate(findings, 1):
        if not isinstance(finding, dict):
            continue
        cwe = str(finding.get("cwe_id") or finding.get("cwe") or "").strip()
        severity = str(finding.get("severity") or "LOW").upper()
        if severity not in {"HIGH", "MEDIUM", "LOW"}:
            severity = "LOW"
        line = int(finding.get("line_number") or finding.get("line") or 0)
        title = str(finding.get("title") or "LLM audit finding")
        reason = str(finding.get("reason") or finding.get("description") or "")
        recommendation = str(finding.get("recommendation") or "")
        description = reason
        if recommendation:
            description = f"{reason}\n\nRecommendation: {recommendation}".strip()

        rule_suffix = cwe or f"F{idx}"
        vulns.append(VulnerabilityReport(
            id=f"llm_audit_{idx}_{line}",
            tool="llm_audit",
            rule_id=f"LLM-AUDIT-{rule_suffix}",
            severity=severity,
            confidence="MEDIUM",
            title=title,
            description=description,
            file_path=filename,
            line_number=line,
            code_snippet=str(finding.get("evidence") or ""),
            cwe_id=cwe or None,
            language=lang,
            more_info="LLM clean audit: static/live scan missed finding",
        ))
    return vulns


def _validate_syntax(patches: list, lang: str):
    """패치 코드의 문법을 검증합니다."""
    from validator.syntax_checker import SyntaxChecker
    checker = SyntaxChecker()
    for p in patches:
        checker.check(p, language=lang)


def _validate_security(patches: list, vuln_reports: list, lang: str, filename: str):
    """패치 코드를 보안 재검증합니다."""
    from validator.security_checker import SecurityChecker
    from shared.schemas import PatchStatus

    vuln_map = {v.id: v for v in vuln_reports}
    sec_checker = SecurityChecker()

    for p in patches:
        if p.status == PatchStatus.FAILED:
            continue
        vuln = vuln_map.get(p.vulnerability_id)
        orig = (vuln.function_code or vuln.code_snippet or "") if vuln else ""
        sec_checker.check(p, language=lang, filename=filename, original_code=orig)
        _apply_blue_team_context(p, vuln)


def _apply_blue_team_context(patch, vuln):
    """Blue Team 관점의 방어 결과와 잔여 위험을 보강합니다."""
    from shared.red_blue import enrich_patch

    enriched = enrich_patch(
        patch.to_dict(),
        vuln.to_dict() if vuln else None,
    )
    patch.blue_team_phase = enriched.get("blue_team_phase", "")
    patch.defense_strategy = enriched.get("defense_strategy", "")
    patch.defense_outcome = enriched.get("defense_outcome", "")
    patch.residual_risk = enriched.get("residual_risk", "")
    patch.defense_plan = enriched.get("defense_plan", {})


def _build_result(
    job_id: str, vuln_reports: list, patches: list, elapsed: float
) -> dict:
    """분석 결과를 세션 딕셔너리로 조립합니다."""
    from shared.schemas import AnalysisSession

    session = AnalysisSession(
        session_id=job_id,
        repo="dashboard-upload",
        pr_number=0,
        commit_sha="direct-upload",
        vulnerabilities=vuln_reports,
        patches=patches,
    )
    session.update_stats()
    session.completed_at = datetime.now().isoformat()
    session.duration_seconds = round(elapsed, 2)
    result = session.to_dict()

    # Patches may skip revalidation when LLM is unavailable, so still add
    # Blue Team context for drafted or failed suggestions.
    from shared.red_blue import enrich_patch, build_red_blue_summary
    vuln_map = {v["id"]: v for v in result.get("vulnerabilities", [])}
    result["patches"] = [
        enrich_patch(p, vuln_map.get(p.get("vulnerability_id")))
        for p in result.get("patches", [])
    ]
    result["red_blue_summary"] = build_red_blue_summary(
        result.get("vulnerabilities", []),
        result.get("patches", []),
    )
    result["analysis_mode"] = "red_blue"
    return result


def _persist_to_db(result_data: dict) -> str | None:
    """결과를 DB에 저장합니다. 실패 시 에러 메시지 반환."""
    try:
        from db import service as db_service
        db_service.save_analysis(result_data)
        return None
    except Exception as e:
        logger.warning(f"[PIPELINE] DB 저장 실패: {e}")
        return str(e)


def _build_optimization_config(
    cve_scope: Optional[list[str]] = None,
    cwe_scope: Optional[list[str]] = None,
    rule_scope: Optional[list[str]] = None,
    max_llm_targets: Optional[int] = None,
    max_context_chars: Optional[int] = None,
    batch_llm: Optional[bool] = None,
):
    """Load LLM optimization defaults and apply API overrides."""
    from shared.llm_optimization import LLMOptimizationConfig

    cfg = _load_config().get("llm", {}).get("optimization", {})
    llm_cfg = _load_config().get("llm", {})
    return LLMOptimizationConfig(
        enabled=bool(cfg.get("enabled", True)),
        cve_scope=_scope_list(cve_scope if cve_scope is not None else cfg.get("cve_scope", [])),
        cwe_scope=_scope_list(cwe_scope if cwe_scope is not None else cfg.get("cwe_scope", [])),
        rule_scope=_scope_list(rule_scope if rule_scope is not None else cfg.get("rule_scope", [])),
        max_targets=int(max_llm_targets if max_llm_targets is not None else cfg.get("max_targets", 10)),
        max_context_chars=int(max_context_chars if max_context_chars is not None else cfg.get("max_context_chars", 2400)),
        batch_enabled=bool(batch_llm if batch_llm is not None else cfg.get("batch_enabled", True)),
        batch_size=int(llm_cfg.get("batch_size", cfg.get("batch_size", 5))),
    )


def _optimize_llm_targets(llm_targets: list, opt_config) -> tuple[list, dict]:
    from shared.llm_optimization import optimize_llm_targets
    return optimize_llm_targets(llm_targets, opt_config)


def _load_config() -> dict:
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "config.yaml")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _scope_list(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return [str(v).strip() for v in value if str(v).strip()]
