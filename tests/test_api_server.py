"""API 서버 엔드포인트 테스트"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from api.server import app

client = TestClient(app)


class TestAPIEndpoints:
    """FastAPI 엔드포인트 테스트"""

    def test_root(self):
        """루트 엔드포인트"""
        r = client.get("/")
        assert r.status_code == 200
        assert r.json()["message"] == "Dallo DevSecOps API"

    def test_stats(self):
        """통계 엔드포인트"""
        r = client.get("/api/stats")
        assert r.status_code == 200
        data = r.json()
        assert "total_issues" in data
        assert "high" in data
        assert "medium" in data
        assert "low" in data

    def test_vulnerabilities(self):
        """취약점 목록 엔드포인트"""
        r = client.get("/api/vulnerabilities")
        assert r.status_code == 200
        data = r.json()
        assert "count" in data
        assert "vulnerabilities" in data
        assert isinstance(data["vulnerabilities"], list)

    def test_vulnerabilities_filter_severity(self):
        """취약점 심각도 필터"""
        r = client.get("/api/vulnerabilities?severity=HIGH")
        assert r.status_code == 200
        data = r.json()
        for v in data["vulnerabilities"]:
            assert v["severity"] == "HIGH"

    def test_vulnerabilities_by_file(self):
        """파일별 취약점 집계"""
        r = client.get("/api/vulnerabilities/by-file")
        assert r.status_code == 200
        data = r.json()
        assert "files" in data
        for f in data["files"]:
            assert "file" in f
            assert "total" in f

    def test_vulnerabilities_by_type(self):
        """유형별 취약점 집계"""
        r = client.get("/api/vulnerabilities/by-type")
        assert r.status_code == 200
        data = r.json()
        assert "types" in data
        for t in data["types"]:
            assert "rule_id" in t
            assert "count" in t

    def test_patches(self):
        """패치 목록 엔드포인트"""
        r = client.get("/api/patches")
        assert r.status_code == 200
        data = r.json()
        assert "count" in data
        assert "patches" in data

    def test_sessions(self):
        """세션 이력 엔드포인트"""
        r = client.get("/api/sessions")
        assert r.status_code == 200
        data = r.json()
        assert "count" in data
        assert "sessions" in data
