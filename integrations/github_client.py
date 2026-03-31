"""
GitHub API 연동 클라이언트

Pull Request 정보 조회, 변경 파일 목록 확인,
코멘트 작성 등 GitHub 관련 작업을 처리합니다.
"""

import os
import json
import requests
from dataclasses import dataclass
from typing import Optional


@dataclass
class PRInfo:
    """Pull Request 정보"""
    owner: str
    repo: str
    pr_number: int
    head_sha: str
    base_branch: str
    head_branch: str
    title: str
    changed_files: list[str]


class GitHubClient:
    """GitHub API 클라이언트"""

    BASE_URL = "https://api.github.com"

    def __init__(self, token: Optional[str] = None):
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def get_pr_info(self, owner: str, repo: str, pr_number: int) -> PRInfo:
        """PR 기본 정보 조회"""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/pulls/{pr_number}"
        resp = requests.get(url, headers=self.headers)
        resp.raise_for_status()
        data = resp.json()

        # 변경된 파일 목록
        files_url = f"{url}/files"
        files_resp = requests.get(files_url, headers=self.headers)
        files_resp.raise_for_status()
        changed_files = [f["filename"] for f in files_resp.json()]

        return PRInfo(
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            head_sha=data["head"]["sha"],
            base_branch=data["base"]["ref"],
            head_branch=data["head"]["ref"],
            title=data["title"],
            changed_files=changed_files,
        )

    def get_changed_python_files(self, owner: str, repo: str, pr_number: int) -> list[str]:
        """PR에서 변경된 Python 파일만 추출"""
        pr_info = self.get_pr_info(owner, repo, pr_number)
        return [f for f in pr_info.changed_files if f.endswith(".py")]

    def create_pr_comment(self, owner: str, repo: str, pr_number: int, body: str) -> dict:
        """PR에 일반 코멘트 작성"""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/issues/{pr_number}/comments"
        payload = {"body": body}
        resp = requests.post(url, headers=self.headers, json=payload)
        resp.raise_for_status()
        return resp.json()

    def create_review_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
        commit_id: str,
        path: str,
        line: int,
    ) -> dict:
        """PR의 특정 코드 라인에 리뷰 코멘트 작성"""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/pulls/{pr_number}/comments"
        payload = {
            "body": body,
            "commit_id": commit_id,
            "path": path,
            "line": line,
        }
        resp = requests.post(url, headers=self.headers, json=payload)
        resp.raise_for_status()
        return resp.json()

    def create_check_run(
        self,
        owner: str,
        repo: str,
        head_sha: str,
        name: str,
        status: str,
        conclusion: Optional[str] = None,
        summary: str = "",
        text: str = "",
    ) -> dict:
        """Check Run 생성 (PR 상태 표시)"""
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/check-runs"
        payload = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
            "output": {
                "title": name,
                "summary": summary,
                "text": text,
            },
        }
        if conclusion:
            payload["conclusion"] = conclusion

        resp = requests.post(url, headers=self.headers, json=payload)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def from_github_event() -> tuple[str, str, int]:
        """GitHub Actions 환경에서 이벤트 정보 추출"""
        event_path = os.environ.get("GITHUB_EVENT_PATH", "")
        if not event_path or not os.path.exists(event_path):
            raise RuntimeError("GITHUB_EVENT_PATH가 설정되지 않았습니다.")

        with open(event_path, "r") as f:
            event = json.load(f)

        repo_full = os.environ.get("GITHUB_REPOSITORY", "")
        if "/" not in repo_full:
            raise RuntimeError("GITHUB_REPOSITORY 형식이 올바르지 않습니다.")

        owner, repo = repo_full.split("/", 1)
        pr_number = event.get("pull_request", {}).get("number")

        if not pr_number:
            raise RuntimeError("Pull Request 이벤트가 아닙니다.")

        return owner, repo, pr_number
