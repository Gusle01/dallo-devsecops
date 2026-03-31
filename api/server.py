"""
API 서버 (api/server.py)

React 대시보드가 이 API를 호출하여 데이터를 가져갑니다.

실행:
  pip install fastapi uvicorn
  uvicorn api.server:app --reload --port 8000
"""

from fastapi import FastAPI, Query, UploadFile, File, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
import json
import os
import sys
import tempfile
import shutil
import time
import uuid
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv()

app = FastAPI(
    title="Dallo DevSecOps API",
    description="보안 분석 결과 조회 API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# React 대시보드 빌드 파일 서빙
DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard", "dist")
if os.path.exists(DASHBOARD_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(DASHBOARD_DIR, "assets")), name="static")

from db.models import init_db
from db import service as db_service

# DB 초기화 (테이블 생성)
init_db()

REPORTS_DIR = "reports"
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 분석 작업 상태 저장 (메모리)
analysis_jobs = {}


class AnalyzeRequest(BaseModel):
    code: str
    filename: str = "uploaded_code.py"
    use_llm: bool = True
    provider: str = "gemini"
    model: str = "gemini-2.5-flash"


# ============================================================
# 헬퍼 함수
# ============================================================

def load_bandit_report() -> dict:
    """Bandit 리포트 로드"""
    path = os.path.join(REPORTS_DIR, "bandit_report.json")
    if not os.path.exists(path):
        return {"results": [], "metrics": {"_totals": {}}}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_full_result() -> dict:
    """전체 파이프라인 결과 로드 (LLM 패치 포함)"""
    path = os.path.join(REPORTS_DIR, "full_result.json")
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ============================================================
# API 엔드포인트
# ============================================================

@app.get("/")
def root():
    return {"message": "Dallo DevSecOps API", "version": "1.0.0"}


@app.get("/api/stats")
def get_stats():
    """대시보드 메인 통계 (DB 우선, 폴백: JSON 파일)"""
    stats = db_service.get_stats()
    if stats.get("total_issues", 0) > 0:
        return stats

    # DB에 데이터 없으면 JSON 파일 폴백
    full = load_full_result()
    if full:
        summary = full.get("summary", {})
        return {
            "total_issues": summary.get("total", 0),
            "high": summary.get("high", 0),
            "medium": summary.get("medium", 0),
            "low": summary.get("low", 0),
            "patches_generated": summary.get("patches_generated", 0),
            "patches_verified": summary.get("patches_verified", 0),
            "duration_seconds": full.get("duration_seconds"),
            "session_id": full.get("session_id", ""),
        }

    report = load_bandit_report()
    totals = report.get("metrics", {}).get("_totals", {})
    results = report.get("results", [])
    return {
        "total_issues": len(results),
        "high": totals.get("SEVERITY.HIGH", 0),
        "medium": totals.get("SEVERITY.MEDIUM", 0),
        "low": totals.get("SEVERITY.LOW", 0),
        "patches_generated": 0,
        "patches_verified": 0,
    }


@app.get("/api/vulnerabilities")
def get_vulnerabilities(
    severity: Optional[str] = Query(None, description="HIGH, MEDIUM, LOW"),
    tool: Optional[str] = Query(None, description="bandit, sonarqube"),
    file_path: Optional[str] = Query(None, description="파일 경로 필터"),
):
    """취약점 목록 조회 (필터 지원)"""
    full = load_full_result()

    if full and full.get("vulnerabilities"):
        vulns = full["vulnerabilities"]
    else:
        report = load_bandit_report()
        vulns = []
        for item in report.get("results", []):
            cwe = item.get("issue_cwe", {})
            vulns.append({
                "id": f"vuln_{item.get('test_id', '')}_{item.get('line_number', 0)}",
                "tool": "bandit",
                "rule_id": item.get("test_id", ""),
                "title": item.get("test_name", ""),
                "severity": item.get("issue_severity", ""),
                "confidence": item.get("issue_confidence", ""),
                "description": item.get("issue_text", ""),
                "file_path": item.get("filename", ""),
                "line_number": item.get("line_number", 0),
                "code_snippet": item.get("code", ""),
                "cwe_id": f"CWE-{cwe['id']}" if isinstance(cwe, dict) and cwe.get("id") else None,
                "more_info": item.get("more_info", ""),
            })

    # 필터
    if severity:
        vulns = [v for v in vulns if v.get("severity", "").upper() == severity.upper()]
    if tool:
        vulns = [v for v in vulns if v.get("tool", "").lower() == tool.lower()]
    if file_path:
        vulns = [v for v in vulns if file_path in v.get("file_path", "")]

    return {"count": len(vulns), "vulnerabilities": vulns}


@app.get("/api/vulnerabilities/by-file")
def get_vulnerabilities_by_file():
    """파일별 취약점 수 집계"""
    data = get_vulnerabilities(severity=None, tool=None, file_path=None)
    vulns = data["vulnerabilities"]

    file_counts = {}
    for v in vulns:
        fp = v.get("file_path", "unknown")
        if fp not in file_counts:
            file_counts[fp] = {"file": fp, "high": 0, "medium": 0, "low": 0, "total": 0}
        sev = v.get("severity", "LOW").lower()
        if sev in file_counts[fp]:
            file_counts[fp][sev] += 1
        file_counts[fp]["total"] += 1

    return {"files": list(file_counts.values())}


@app.get("/api/vulnerabilities/by-type")
def get_vulnerabilities_by_type():
    """취약점 유형별 집계"""
    data = get_vulnerabilities(severity=None, tool=None, file_path=None)
    vulns = data["vulnerabilities"]

    type_counts = {}
    for v in vulns:
        rule = v.get("rule_id", "unknown")
        name = v.get("title", "unknown")
        key = f"{rule}:{name}"
        if key not in type_counts:
            type_counts[key] = {"rule_id": rule, "name": name, "count": 0, "severity": v.get("severity", "")}
        type_counts[key]["count"] += 1

    return {"types": list(type_counts.values())}


@app.get("/api/patches")
def get_patches():
    """LLM 수정 제안 목록"""
    full = load_full_result()
    patches = full.get("patches", [])

    # 취약점 정보와 매칭
    vulns = {v.get("id"): v for v in full.get("vulnerabilities", [])}
    enriched = []
    for p in patches:
        vuln = vulns.get(p.get("vulnerability_id"), {})
        enriched.append({
            **p,
            "file_path": vuln.get("file_path", ""),
            "line_number": vuln.get("line_number", 0),
            "rule_id": vuln.get("rule_id", ""),
            "severity": vuln.get("severity", ""),
            "title": vuln.get("title", ""),
            "original_code": vuln.get("function_code") or vuln.get("code_snippet", ""),
        })

    return {"count": len(enriched), "patches": enriched}


@app.get("/api/sessions")
def get_sessions():
    """분석 세션 이력 (DB)"""
    sessions = db_service.get_all_sessions()
    return {"count": len(sessions), "sessions": sessions}


@app.get("/api/sessions/{session_id}")
def get_session_detail(session_id: str):
    """특정 세션 상세 조회"""
    result = db_service.get_analysis_by_session(session_id)
    if not result:
        return {"error": "Session not found"}
    return result


# ============================================================
# 코드 분석 실행 API
# ============================================================

def _run_analysis(job_id: str, code: str, filename: str, use_llm: bool, provider: str, model: str):
    """백그라운드에서 분석 파이프라인 실행"""
    from analyzer.semgrep_runner import detect_and_run, SemgrepRunner, EXTENSION_MAP
    from analyzer.bandit_runner import BanditRunner
    from analyzer.context_extractor import ContextExtractor
    from shared.schemas import VulnerabilityReport, AnalysisSession, PatchStatus

    analysis_jobs[job_id]["status"] = "analyzing"
    start_time = time.time()

    try:
        # 임시 디렉토리에 코드 저장
        tmp_dir = tempfile.mkdtemp(prefix="dallo_analyze_")
        file_path = os.path.join(tmp_dir, filename)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(code)

        # Step 1: 언어 감지 + 적절한 분석기 실행
        ext = os.path.splitext(filename)[1].lower()
        lang = EXTENSION_MAP.get(ext, "unknown")
        analysis_jobs[job_id]["language"] = lang

        if ext == ".py":
            analysis_jobs[job_id]["step"] = "Bandit + Semgrep 정적 분석 중..."
        else:
            analysis_jobs[job_id]["step"] = f"Semgrep 정적 분석 중... ({lang})"

        result = detect_and_run(file_path)

        # Step 2: 코드 문맥 추출
        analysis_jobs[job_id]["step"] = "코드 문맥 추출 중..."
        extractor = ContextExtractor(context_lines=10)
        contexts = extractor.extract_batch(result.vulnerabilities)

        context_map = {}
        for ctx in contexts:
            key = (ctx.vulnerability.file_path, ctx.vulnerability.line_number)
            context_map[key] = ctx

        # VulnerabilityReport 변환
        vuln_reports = []
        for vuln in result.vulnerabilities:
            key = (vuln.file_path, vuln.line_number)
            ctx = context_map.get(key)
            vuln_reports.append(VulnerabilityReport(
                id=f"vuln_{vuln.rule_id}_{vuln.line_number}",
                tool=vuln.tool,
                rule_id=vuln.rule_id,
                severity=vuln.severity,
                confidence=vuln.confidence,
                title=vuln.title,
                description=vuln.description,
                file_path=filename,  # 원래 파일명 사용
                line_number=vuln.line_number,
                code_snippet=vuln.code_snippet,
                function_code=ctx.full_function if ctx else "",
                file_imports=ctx.file_imports if ctx else "",
                cwe_id=vuln.cwe_id,
            ))

        # Step 3: LLM 수정안 생성
        patches = []
        if use_llm and vuln_reports:
            analysis_jobs[job_id]["step"] = "AI 수정안 생성 중..."
            try:
                from agent.llm_agent import DalloAgent
                agent = DalloAgent(provider=provider, model=model)
                patches = agent.generate_patches(vuln_reports)
            except Exception as e:
                analysis_jobs[job_id]["llm_error"] = str(e)

        # Step 4: 코드 검증
        if patches:
            analysis_jobs[job_id]["step"] = "코드 검증 중..."
            from validator.syntax_checker import SyntaxChecker
            checker = SyntaxChecker()
            checker.check_batch(patches)

        # 결과 조립
        elapsed = time.time() - start_time
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

        result_data = session.to_dict()

        # JSON 파일로 저장
        os.makedirs(REPORTS_DIR, exist_ok=True)
        with open(os.path.join(REPORTS_DIR, "full_result.json"), "w", encoding="utf-8") as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)

        # DB에 저장
        try:
            db_service.save_analysis(result_data)
        except Exception as e:
            analysis_jobs[job_id]["db_error"] = str(e)

        analysis_jobs[job_id]["status"] = "completed"
        analysis_jobs[job_id]["result"] = result_data
        analysis_jobs[job_id]["step"] = "완료"

        # 임시 디렉토리 정리
        shutil.rmtree(tmp_dir, ignore_errors=True)

    except Exception as e:
        analysis_jobs[job_id]["status"] = "failed"
        analysis_jobs[job_id]["error"] = str(e)
        analysis_jobs[job_id]["step"] = f"오류: {str(e)}"


@app.post("/api/analyze")
def start_analysis(req: AnalyzeRequest, background_tasks: BackgroundTasks):
    """코드를 제출하여 분석을 시작합니다."""
    job_id = f"job_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"

    analysis_jobs[job_id] = {
        "job_id": job_id,
        "status": "queued",
        "step": "대기 중...",
        "filename": req.filename,
        "code_length": len(req.code),
        "use_llm": req.use_llm,
        "created_at": datetime.now().isoformat(),
        "result": None,
        "error": None,
    }

    background_tasks.add_task(
        _run_analysis, job_id, req.code, req.filename,
        req.use_llm, req.provider, req.model,
    )

    return {"job_id": job_id, "status": "queued", "message": "분석이 시작되었습니다."}


@app.get("/api/analyze/{job_id}")
def get_analysis_status(job_id: str):
    """분석 작업 상태를 조회합니다."""
    job = analysis_jobs.get(job_id)
    if not job:
        return {"error": "Job not found"}
    return job


@app.post("/api/analyze/file")
async def analyze_file(file: UploadFile = File(...), use_llm: bool = Form(True)):
    """파일을 업로드하여 분석합니다."""
    content = await file.read()
    code = content.decode("utf-8")

    req = AnalyzeRequest(code=code, filename=file.filename or "uploaded.py", use_llm=use_llm)

    # 동기 실행 (파일 업로드는 즉시 결과 반환)
    job_id = f"job_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    analysis_jobs[job_id] = {
        "job_id": job_id, "status": "queued", "step": "시작",
        "filename": req.filename, "created_at": datetime.now().isoformat(),
        "result": None, "error": None,
    }

    from threading import Thread
    t = Thread(target=_run_analysis, args=(job_id, req.code, req.filename, req.use_llm, req.provider, req.model))
    t.start()

    return {"job_id": job_id, "status": "queued"}


# ============================================================
# 대시보드 (React SPA) — API 라우트 이후에 배치
# ============================================================

@app.get("/dashboard")
@app.get("/dashboard/{path:path}")
def serve_dashboard(path: str = ""):
    """React 대시보드 서빙"""
    if os.path.exists(DASHBOARD_DIR):
        return FileResponse(os.path.join(DASHBOARD_DIR, "index.html"))
    return {"error": "Dashboard not built. Run: cd dashboard && npm run build"}
