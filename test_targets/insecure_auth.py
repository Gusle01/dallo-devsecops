"""
보안 취약점 테스트: 인증/인가 관련 취약점

포함된 취약점:
- 하드코딩된 비밀번호 (CWE-798)
- 취약한 비밀번호 해싱 (CWE-327)
- 평문 비밀번호 비교 (CWE-256)
"""

import hashlib
import sqlite3
import os


# [취약] 하드코딩된 관리자 비밀번호 (CWE-798)
ADMIN_PASSWORD = "admin123!"
SECRET_KEY = "my-secret-jwt-key-do-not-share"
DATABASE_PASSWORD = "root_password"


def authenticate_user(username: str, password: str) -> bool:
    """취약: 평문 비밀번호 비교"""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # [취약] SQL Injection + 평문 비밀번호 저장
    query = f"SELECT password FROM users WHERE username = '{username}'"
    cursor.execute(query)
    row = cursor.fetchone()

    if row and row[0] == password:  # [취약] 평문 비교
        return True
    return False


def hash_token(token: str) -> str:
    """취약: MD5로 토큰 해싱"""
    # [취약] MD5 사용
    return hashlib.md5(token.encode()).hexdigest()


def create_temp_file(user_input: str) -> str:
    """취약: 임시 파일 생성 시 사용자 입력 사용"""
    # [취약] 경로 조작 가능
    filepath = f"/tmp/{user_input}.txt"
    with open(filepath, "w") as f:
        f.write("temp data")
    return filepath


def run_admin_command(cmd: str) -> str:
    """취약: 관리자 명령 실행"""
    # [취약] os.system + 사용자 입력
    os.system(cmd)
    return "executed"
