#!/usr/bin/env python3
"""
Dallo DevSecOps — 원클릭 실행 스크립트

사용법:
    python start.py              # 서버 시작 (포트 8000)
    python start.py --port 8080  # 포트 지정
    python start.py --setup      # 의존성 설치 + DB 초기화 + 서버 시작
"""

import subprocess
import sys
import os
import argparse


def check_python():
    v = sys.version_info
    print(f"  Python: {v.major}.{v.minor}.{v.micro}")
    if v < (3, 10):
        print("  ⚠️  Python 3.10 이상이 필요합니다.")
        sys.exit(1)
    print("  ✅ Python 버전 OK")


def install_deps():
    print("\n📦 의존성 설치 중...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "-q"], check=True)
    print("  ✅ 의존성 설치 완료")


def setup_env():
    if not os.path.exists(".env"):
        if os.path.exists(".env.example"):
            import shutil
            shutil.copy(".env.example", ".env")
            print("  ✅ .env 파일 생성 (.env.example 복사)")
            print("  ⚠️  .env 파일에 API 키를 설정하세요")
        else:
            print("  ⚠️  .env.example이 없습니다")
    else:
        print("  ✅ .env 파일 존재")


def init_db():
    print("\n🗄️  DB 초기화 중...")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from db.models import init_db as _init_db, engine
    _init_db()
    print(f"  DB: {engine.url}")


def seed_sample_data():
    """reports/full_result.json이 있으면 DB에 저장"""
    report_path = os.path.join("reports", "full_result.json")
    if os.path.exists(report_path):
        import json
        from db.service import save_analysis, get_stats
        with open(report_path, "r") as f:
            data = json.load(f)
        save_analysis(data)
        stats = get_stats()
        print(f"  ✅ 기존 분석 결과 DB 로드 ({stats['total_issues']}건)")
    else:
        print("  ℹ️  기존 분석 결과 없음 — 대시보드에서 분석을 실행하세요")


def build_dashboard():
    """대시보드 빌드 (node가 있는 경우)"""
    dist_dir = os.path.join("dashboard", "dist", "index.html")
    if os.path.exists(dist_dir):
        print("  ✅ 대시보드 빌드 파일 존재")
        return True

    print("\n🎨 대시보드 빌드 중...")
    node_modules = os.path.join("dashboard", "node_modules")
    if not os.path.exists(node_modules):
        print("  ⚠️  dashboard/node_modules가 없습니다.")
        print("     cd dashboard && npm install && npm run build")
        print("  ℹ️  대시보드 없이 API만 실행합니다.")
        return False

    try:
        subprocess.run(["node", "node_modules/vite/bin/vite.js", "build"],
                       cwd="dashboard", capture_output=True, timeout=30)
        print("  ✅ 대시보드 빌드 완료")
        return True
    except Exception:
        print("  ⚠️  대시보드 빌드 실패 — API만 실행합니다.")
        return False


def start_server(port: int):
    dashboard_path = os.path.join("dashboard", "dist", "index.html")
    has_dashboard = os.path.exists(dashboard_path)

    print(f"\n🚀 서버 시작!")
    print(f"   API:       http://localhost:{port}")
    print(f"   API Docs:  http://localhost:{port}/docs")
    if has_dashboard:
        print(f"   Dashboard: http://localhost:{port}/dashboard")
    print(f"\n   종료: Ctrl+C\n")

    subprocess.run([
        sys.executable, "-m", "uvicorn",
        "api.server:app",
        "--host", "0.0.0.0",
        "--port", str(port),
        "--reload",
    ])


def main():
    parser = argparse.ArgumentParser(description="Dallo DevSecOps 서버")
    parser.add_argument("--port", type=int, default=8000, help="서버 포트 (기본: 8000)")
    parser.add_argument("--setup", action="store_true", help="의존성 설치 + DB 초기화 포함")
    args = parser.parse_args()

    print("=" * 50)
    print("  🛡️  Dallo DevSecOps")
    print("=" * 50)

    check_python()

    if args.setup:
        install_deps()

    setup_env()
    init_db()
    seed_sample_data()
    build_dashboard()
    start_server(args.port)


if __name__ == "__main__":
    main()
