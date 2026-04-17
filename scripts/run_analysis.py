#!/usr/bin/env python3
"""
전체 분석 파이프라인 실행 스크립트

분석 → LLM 수정안 생성 → 코드 검증 → PR 코멘트 전체 흐름을 실행합니다.

사용법:
  python scripts/run_analysis.py --target test_targets/
  python scripts/run_analysis.py --target test_targets/sql_injection.py --severity HIGH
  python scripts/run_analysis.py --target test_targets/ --provider gemini --model gemini-2.0-flash-lite
  python scripts/run_analysis.py --target test_targets/ --json-output reports/full_result.json
"""

import argparse
import json
import sys
import os
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from analyzer.bandit_runner import BanditRunner
from analyzer.context_extractor import ContextExtractor
from analyzer.result_parser import filter_by_severity
from integrations.pr_commenter import PRCommenter
from shared.schemas import VulnerabilityReport, AnalysisSession, PatchStatus


def print_header(text: str):
    width = 60
    print()
    print("=" * width)
    print(f"  {text}")
    print("=" * width)


def print_vuln(vuln, idx: int):
    emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}.get(vuln.severity, "⚪")
    print(f"\n  {idx}. {emoji} [{vuln.severity}] {vuln.rule_id} — {vuln.title}")
    print(f"     파일: {vuln.file_path}:{vuln.line_number}")
    print(f"     설명: {vuln.description}")
    if vuln.cwe_id:
        print(f"     CWE:  {vuln.cwe_id}")


def bandit_vuln_to_report(vuln, ctx=None) -> VulnerabilityReport:
    """Bandit Vulnerability + CodeContext → shared VulnerabilityReport 변환"""
    return VulnerabilityReport(
        id=f"vuln_{vuln.rule_id}_{vuln.line_number}",
        tool=vuln.tool,
        rule_id=vuln.rule_id,
        severity=vuln.severity,
        confidence=vuln.confidence,
        title=vuln.title,
        description=vuln.description,
        file_path=vuln.file_path,
        line_number=vuln.line_number,
        code_snippet=vuln.code_snippet,
        function_code=ctx.full_function if ctx else "",
        file_imports=ctx.file_imports if ctx else "",
        cwe_id=vuln.cwe_id,
        more_info=vuln.more_info,
    )


def main():
    parser = argparse.ArgumentParser(description="Dallo 보안 분석 파이프라인")
    parser.add_argument("--target", "-t", required=True, help="분석할 디렉토리 또는 파일 경로")
    parser.add_argument("--severity", "-s", default="LOW", choices=["HIGH", "MEDIUM", "LOW"],
                        help="최소 심각도 필터 (기본: LOW = 전체)")
    parser.add_argument("--output", "-o", default="reports/bandit_report.json", help="리포트 저장 경로")
    parser.add_argument("--context-lines", "-c", type=int, default=10, help="취약점 주변 코드 추출 범위")
    parser.add_argument("--markdown", action="store_true", help="마크다운 PR 코멘트 출력")
    parser.add_argument("--json-output", help="전체 결과를 JSON 파일로 저장")
    parser.add_argument("--provider", default="gemini", choices=["openai", "gemini", "anthropic"],
                        help="LLM 프로바이더 (기본: gemini)")
    parser.add_argument("--model", default=None, help="LLM 모델 (기본: 프로바이더별 기본값)")
    parser.add_argument("--skip-llm", action="store_true", help="LLM 수정안 생성 건너뛰기")
    parser.add_argument("--skip-verify", action="store_true", help="코드 검증 건너뛰기")

    args = parser.parse_args()
    start_time = time.time()

    # ========================================
    # Step 1: Bandit 정적 분석 실행
    # ========================================
    print_header("Step 1: Bandit 정적 분석 실행")
    print(f"  대상: {args.target}")

    runner = BanditRunner(config_path="config/bandit.yml")
    result = runner.run(args.target, output_path=args.output)

    if result.error:
        print(f"\n  [!] 오류: {result.error}")
        sys.exit(1)

    print(f"\n  [+] 분석 완료!")
    print(f"      전체: {result.total_issues}건")
    print(f"      HIGH: {result.high_count} | MEDIUM: {result.medium_count} | LOW: {result.low_count}")
    print(f"      리포트 저장: {args.output}")

    # ========================================
    # Step 2: 심각도 필터링
    # ========================================
    if args.severity != "LOW":
        print_header(f"Step 2: 심각도 필터링 ({args.severity} 이상)")
        result = filter_by_severity(result, args.severity)
        print(f"  필터 후: {result.total_issues}건")
    else:
        print_header("Step 2: 심각도 필터링 (전체)")
        print(f"  필터 없음 — 전체 {result.total_issues}건 표시")

    # ========================================
    # Step 3: 취약점 목록 출력
    # ========================================
    print_header("Step 3: 탐지된 취약점 목록")

    if not result.vulnerabilities:
        print("\n  ✅ 취약점이 발견되지 않았습니다!")
        return

    for idx, vuln in enumerate(result.vulnerabilities, 1):
        print_vuln(vuln, idx)

    # ========================================
    # Step 4: 코드 문맥 추출
    # ========================================
    print_header("Step 4: 코드 문맥 추출")

    extractor = ContextExtractor(context_lines=args.context_lines)
    contexts = extractor.extract_batch(result.vulnerabilities)

    print(f"  {len(contexts)}건의 코드 문맥 추출 완료")

    if contexts:
        print(f"\n  [샘플] {contexts[0].vulnerability.file_path}:{contexts[0].vulnerability.line_number}")
        if contexts[0].full_function:
            func_lines = contexts[0].full_function.split("\n")
            for line in func_lines[:8]:
                print(f"    {line}")
            if len(func_lines) > 8:
                print(f"    ... (+{len(func_lines) - 8}줄)")

    # VulnerabilityReport로 변환 (LLM 입력용)
    context_map = {}
    for ctx in contexts:
        key = (ctx.vulnerability.file_path, ctx.vulnerability.line_number)
        context_map[key] = ctx

    vuln_reports = []
    for vuln in result.vulnerabilities:
        key = (vuln.file_path, vuln.line_number)
        ctx = context_map.get(key)
        vuln_reports.append(bandit_vuln_to_report(vuln, ctx))

    # ========================================
    # Step 5: LLM 수정안 생성
    # ========================================
    patches = []
    if not args.skip_llm:
        print_header("Step 5: LLM 수정안 생성")
        print(f"  프로바이더: {args.provider}")
        print(f"  모델: {args.model or '(기본값)'}")

        try:
            from agent.llm_agent import DalloAgent

            agent = DalloAgent(
                provider=args.provider,
                model=args.model,
            )
            print(f"  사용 모델: {agent.model}")
            print(f"  처리할 취약점: {len(vuln_reports)}건")
            print()

            for i, vr in enumerate(vuln_reports, 1):
                emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}.get(vr.severity, "⚪")
                print(f"  [{i}/{len(vuln_reports)}] {emoji} {vr.rule_id} ({vr.file_path}:{vr.line_number})...", end=" ", flush=True)
                patch = agent.generate_patch(vr)
                patches.append(patch)
                status_icon = "✅" if patch.status == PatchStatus.GENERATED else "❌"
                print(f"{status_icon} {patch.status}")

            generated = sum(1 for p in patches if p.status == PatchStatus.GENERATED)
            print(f"\n  [+] 수정안 생성: {generated}/{len(patches)}건 성공")

        except Exception as e:
            print(f"\n  [!] LLM 에이전트 오류: {e}")
            print("  → --skip-llm 옵션으로 건너뛸 수 있습니다.")
    else:
        print_header("Step 5: LLM 수정안 생성 (건너뜀)")

    # ========================================
    # Step 6: 코드 검증
    # ========================================
    if patches and not args.skip_verify:
        print_header("Step 6: 코드 검증")

        from validator.syntax_checker import SyntaxChecker
        from validator.test_runner import TestRunner

        checker = SyntaxChecker()
        test_runner = TestRunner()

        for i, patch in enumerate(patches):
            if patch.status == PatchStatus.FAILED:
                continue

            vr = vuln_reports[i]
            print(f"  [{i+1}] {vr.rule_id} — ", end="")

            # 문법 검사 (파일 확장자로 언어 감지)
            import os as _os
            _ext = _os.path.splitext(vr.file_path)[1].lower()
            _lang_map = {".py": "python", ".java": "java", ".js": "javascript", ".ts": "typescript", ".go": "go", ".c": "c", ".cpp": "cpp", ".rs": "rust", ".kt": "kotlin"}
            _lang = _lang_map.get(_ext, "python")
            checker.check(patch, language=_lang)
            if not patch.syntax_valid:
                print(f"❌ 문법 오류")
                continue

            # 테스트 실행
            test_runner.run(patch, vr.file_path)
            status_icon = "✅" if patch.status == PatchStatus.VERIFIED else "⚠️"
            print(f"{status_icon} 문법 통과 | 테스트: {'통과' if patch.test_passed else '실패/없음'} | 상태: {patch.status}")

        verified = sum(1 for p in patches if p.status == PatchStatus.VERIFIED)
        print(f"\n  [+] 검증 결과: {verified}/{len(patches)}건 통과")
    elif not patches:
        print_header("Step 6: 코드 검증 (수정안 없음)")
    else:
        print_header("Step 6: 코드 검증 (건너뜀)")

    # ========================================
    # Step 7: PR 코멘트 포맷 생성
    # ========================================
    # LLM 수정안을 PR 코멘트에 포함
    llm_suggestions = None
    if patches:
        llm_suggestions = []
        for patch in patches:
            llm_suggestions.append({
                "fixed_code": patch.fixed_code,
                "explanation": patch.explanation,
                "status": str(patch.status),
                "syntax_valid": patch.syntax_valid,
                "test_passed": patch.test_passed,
            })

    if args.markdown:
        print_header("Step 7: PR 코멘트 생성")
        commenter = PRCommenter(include_code_context=True)
        comment = commenter.format_summary_comment(
            result,
            contexts=contexts,
            llm_suggestions=llm_suggestions,
        )
        print()
        print(comment)

    # ========================================
    # JSON 출력
    # ========================================
    if args.json_output:
        elapsed = time.time() - start_time

        session = AnalysisSession(
            session_id=f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            repo=os.environ.get("GITHUB_REPOSITORY", "local"),
            pr_number=0,
            commit_sha="local",
            vulnerabilities=vuln_reports,
            patches=patches,
        )
        session.update_stats()
        session.completed_at = datetime.now().isoformat()
        session.duration_seconds = round(elapsed, 2)

        output_data = session.to_dict()

        # 코드 문맥도 포함
        output_data["contexts"] = [
            {
                "file": ctx.file_path,
                "line": ctx.vulnerability.line_number,
                "function": ctx.full_function,
                "imports": ctx.file_imports,
            }
            for ctx in contexts
        ]

        os.makedirs(os.path.dirname(args.json_output) or ".", exist_ok=True)
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        print(f"\n  [+] JSON 결과 저장: {args.json_output}")

    # ========================================
    # 완료
    # ========================================
    elapsed = time.time() - start_time
    print_header("분석 완료")
    print(f"  총 취약점: {result.total_issues}건")
    if patches:
        generated = sum(1 for p in patches if p.status != PatchStatus.FAILED)
        verified = sum(1 for p in patches if p.status == PatchStatus.VERIFIED)
        print(f"  수정안 생성: {generated}건")
        print(f"  검증 통과:   {verified}건")
    print(f"  소요 시간:   {elapsed:.1f}초")
    print()


if __name__ == "__main__":
    main()
