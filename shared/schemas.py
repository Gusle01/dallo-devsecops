"""
공통 데이터 인터페이스 (shared/schemas.py)

팀원 3명이 공유하는 데이터 구조를 정의합니다.

- 이준수: 분석 결과를 이 포맷으로 생성
- 박영주: 이 포맷을 받아서 LLM에 전달, 수정안을 이 포맷으로 반환
- 임해안: 이 포맷을 DB에 저장하고 대시보드에 표시

이 파일을 수정하면 팀원 전체에 영향이 가므로 변경 시 팀 공유 필수!
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime
from enum import Enum
import json


# ============================================================
# 1. 공통 Enum
# ============================================================

class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AnalysisTool(str, Enum):
    BANDIT = "bandit"
    SONARQUBE = "sonarqube"


class PatchStatus(str, Enum):
    PENDING = "pending"          # LLM 수정안 생성 대기
    GENERATED = "generated"      # 수정안 생성 완료
    VERIFIED = "verified"        # 검증 통과
    FAILED = "failed"            # 검증 실패
    APPLIED = "applied"          # 개발자가 적용함
    REJECTED = "rejected"        # 개발자가 거부함


# ============================================================
# 2. 취약점 (이준수 → 박영주, 임해안)
# ============================================================

@dataclass
class VulnerabilityReport:
    """
    정규화된 취약점 정보

    이준수가 Bandit/SonarQube 분석 후 생성.
    박영주가 LLM 입력으로 사용.
    임해안이 DB에 저장.
    """
    id: str                            # 고유 ID (예: "vuln_001")
    tool: str                          # 탐지 도구 (bandit / sonarqube)
    rule_id: str                       # 규칙 ID (예: B608)
    severity: str                      # HIGH / MEDIUM / LOW
    confidence: str                    # HIGH / MEDIUM / LOW
    title: str                         # 취약점 제목
    description: str                   # 설명
    file_path: str                     # 파일 경로
    line_number: int                   # 라인 번호
    code_snippet: str = ""             # 취약점 코드 스니펫
    function_code: str = ""            # 취약점이 포함된 함수 전체
    file_imports: str = ""             # 파일의 import 문
    cwe_id: Optional[str] = None       # CWE ID
    language: str = "python"           # 코드 언어 (python, java, javascript 등)
    more_info: str = ""                # 참고 URL
    risk_level: str = ""               # critical/high/medium/low (위험도 산정 결과)
    cvss_score: float = 0.0            # CVSS 스코어 (0~10)
    duplicate_group_id: str = ""       # 중복 그룹 ID (중복 제거 후 할당)
    created_at: str = ""               # 탐지 시각

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


# ============================================================
# 3. LLM 수정 제안 (박영주 → 이준수, 임해안)
# ============================================================

@dataclass
class PatchSuggestion:
    """
    LLM이 생성한 코드 수정 제안

    박영주가 LLM 응답으로부터 생성.
    이준수가 검증 후 PR 코멘트에 포함.
    임해안이 DB에 저장하고 대시보드에 표시.
    """
    vulnerability_id: str              # 어떤 취약점에 대한 수정인지
    fixed_code: str                    # 수정된 코드
    explanation: str                   # 수정 근거 설명
    fix_type: str = "recommended"      # minimal / recommended / structural
    status: str = PatchStatus.PENDING  # 현재 상태
    syntax_valid: Optional[bool] = None     # 문법 검사 통과 여부
    test_passed: Optional[bool] = None      # 테스트 통과 여부
    security_revalidation: Optional[dict] = None  # 보안 재검증 결과
    created_at: str = ""
    verified_at: Optional[str] = None

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


# ============================================================
# 4. 분석 세션 (전체 파이프라인 1회 실행 결과)
# ============================================================

@dataclass
class AnalysisSession:
    """
    분석 파이프라인 1회 실행의 전체 결과

    GitHub PR 1개당 1개의 AnalysisSession이 생성됨.
    """
    session_id: str                    # 고유 ID
    repo: str                          # GitHub 레포 (owner/repo)
    pr_number: int                     # PR 번호
    commit_sha: str                    # 분석 대상 커밋
    branch: str = ""                   # 브랜치명

    # 분석 결과
    vulnerabilities: list[VulnerabilityReport] = field(default_factory=list)
    patches: list[PatchSuggestion] = field(default_factory=list)

    # 통계
    total_issues: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    patches_generated: int = 0
    patches_verified: int = 0

    # 시간
    started_at: str = ""
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None

    def __post_init__(self):
        if not self.started_at:
            self.started_at = datetime.now().isoformat()

    def update_stats(self):
        """취약점/패치 목록에서 통계를 재계산"""
        self.total_issues = len(self.vulnerabilities)
        self.high_count = sum(1 for v in self.vulnerabilities if v.severity == "HIGH")
        self.medium_count = sum(1 for v in self.vulnerabilities if v.severity == "MEDIUM")
        self.low_count = sum(1 for v in self.vulnerabilities if v.severity == "LOW")
        self.patches_generated = sum(1 for p in self.patches if p.status != PatchStatus.PENDING)
        self.patches_verified = sum(1 for p in self.patches if p.status == PatchStatus.VERIFIED)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "repo": self.repo,
            "pr_number": self.pr_number,
            "commit_sha": self.commit_sha,
            "branch": self.branch,
            "summary": {
                "total": self.total_issues,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "patches_generated": self.patches_generated,
                "patches_verified": self.patches_verified,
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "patches": [p.to_dict() for p in self.patches],
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
