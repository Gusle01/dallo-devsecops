#!/usr/bin/env python3
"""
CI/CD 보안 게이트 (scripts/ci_gate.py)

분석 결과 JSON을 읽어 심각도 임계값을 초과하면 exit code 1을 반환합니다.
GitHub Actions 워크플로우에서 빌드를 차단하는 데 사용합니다.

사용법:
    python scripts/ci_gate.py reports/full_result.json
    python scripts/ci_gate.py reports/full_result.json --config .github/dallo-gate.yml

환경변수 (임계값 오버라이드):
    DALLO_GATE_CRITICAL_THRESHOLD: critical 임계값 (기본: 1)
    DALLO_GATE_HIGH_THRESHOLD: high 임계값 (기본: 5)
"""

import json
import os
import sys


def load_gate_config(config_path: str = None) -> dict:
    """게이트 설정을 로드합니다. (YAML 파일 또는 환경변수)"""
    config = {
        "critical_threshold": 1,
        "high_threshold": 5,
    }

    # 1. YAML 설정 파일
    if config_path and os.path.exists(config_path):
        try:
            import yaml
            with open(config_path, "r", encoding="utf-8") as f:
                file_config = yaml.safe_load(f) or {}
            config["critical_threshold"] = file_config.get("critical_threshold", config["critical_threshold"])
            config["high_threshold"] = file_config.get("high_threshold", config["high_threshold"])
        except Exception as e:
            print(f"[WARN] 설정 파일 로드 실패: {e}")

    # 2. 기본 설정 파일 (.github/dallo-gate.yml)
    elif not config_path:
        default_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                     ".github", "dallo-gate.yml")
        if os.path.exists(default_path):
            return load_gate_config(default_path)

    # 3. 환경변수 오버라이드
    for env_key, config_key in [
        ("DALLO_GATE_CRITICAL_THRESHOLD", "critical_threshold"),
        ("DALLO_GATE_HIGH_THRESHOLD", "high_threshold"),
    ]:
        raw = os.environ.get(env_key)
        if raw:
            try:
                config[config_key] = int(raw)
            except ValueError:
                print(f"[WARN] {env_key}={raw!r} — 정수가 아닙니다. 기본값 {config[config_key]} 사용")

    return config


def check_gate(result_path: str, config: dict) -> tuple[bool, str]:
    """
    분석 결과를 검사하여 게이트 통과 여부를 반환합니다.

    Returns:
        (passed: bool, message: str)
    """
    if not os.path.exists(result_path):
        return True, "Gate Status: PASSED (분석 결과 파일 없음 — 스킵)"

    with open(result_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 취약점 심각도 집계
    vulns = data.get("vulnerabilities", [])
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulns:
        sev = v.get("severity", "").upper()
        # risk_level이 있으면 우선 사용
        risk = v.get("risk_level", "").upper()
        if risk:
            sev = risk.upper()
        if sev in counts:
            counts[sev] += 1

    critical = counts["CRITICAL"]
    high = counts["HIGH"]
    total = len(vulns)

    # 게이트 판정
    reasons = []
    if critical >= config["critical_threshold"]:
        reasons.append(f"CRITICAL {critical}개 >= 임계값 {config['critical_threshold']}")
    if high >= config["high_threshold"]:
        reasons.append(f"HIGH {high}개 >= 임계값 {config['high_threshold']}")

    if reasons:
        msg = f"Gate Status: FAILED\n"
        msg += f"  총 취약점: {total}개 (CRITICAL: {critical}, HIGH: {high}, MEDIUM: {counts['MEDIUM']}, LOW: {counts['LOW']})\n"
        msg += f"  실패 사유:\n"
        for r in reasons:
            msg += f"    - {r}\n"
        return False, msg

    msg = f"Gate Status: PASSED\n"
    msg += f"  총 취약점: {total}개 (CRITICAL: {critical}, HIGH: {high}, MEDIUM: {counts['MEDIUM']}, LOW: {counts['LOW']})\n"
    msg += f"  임계값: CRITICAL < {config['critical_threshold']}, HIGH < {config['high_threshold']}"
    return True, msg


def main():
    if len(sys.argv) < 2:
        print("사용법: python scripts/ci_gate.py <result.json> [--config <config.yml>]")
        sys.exit(1)

    result_path = sys.argv[1]
    config_path = None
    if "--config" in sys.argv:
        idx = sys.argv.index("--config")
        if idx + 1 < len(sys.argv):
            config_path = sys.argv[idx + 1]

    config = load_gate_config(config_path)
    passed, message = check_gate(result_path, config)

    print("=" * 60)
    print("  Dallo DevSecOps — Security Gate")
    print("=" * 60)
    print(message)
    print("=" * 60)

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
