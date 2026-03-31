"""
하드코딩된 비밀번호/API 키 취약점 샘플 코드
- Bandit 탐지 대상: B105, B106, B107 (hardcoded_password)
- OWASP: A07:2021 Identification and Authentication Failures
"""

import hashlib
import hmac

# [취약] 하드코딩된 API 키
API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678"
SECRET_KEY = "my_super_secret_key_2024"
DATABASE_PASSWORD = "admin1234!"

# [취약] 하드코딩된 AWS 자격증명
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def connect_to_database():
    """취약: 비밀번호가 코드에 하드코딩"""
    import psycopg2

    # [취약] 하드코딩된 자격증명
    conn = psycopg2.connect(
        host="production-db.example.com",
        database="main_db",
        user="admin",
        password="P@ssw0rd!2024"
    )
    return conn


def authenticate_user(username: str, password: str) -> bool:
    """취약: 하드코딩된 관리자 비밀번호와 비교"""
    # [취약] 관리자 비밀번호 하드코딩
    ADMIN_PASSWORD = "admin123"

    if username == "admin" and password == ADMIN_PASSWORD:
        return True
    return False


def generate_token(user_id: str) -> str:
    """취약: 하드코딩된 시크릿으로 토큰 생성"""
    # [취약] JWT 시크릿 하드코딩
    secret = "jwt_secret_key_do_not_share"
    payload = f"{user_id}:{secret}"
    return hashlib.sha256(payload.encode()).hexdigest()


def verify_webhook(payload: bytes, signature: str) -> bool:
    """취약: 하드코딩된 시크릿으로 서명 검증"""
    # [취약] Webhook 시크릿 하드코딩
    webhook_secret = b"whsec_abcdef123456"
    expected = hmac.new(webhook_secret, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


class DatabaseConfig:
    """취약: 설정 클래스에 민감 정보 하드코딩"""
    HOST = "10.0.1.100"
    PORT = 5432
    USERNAME = "root"
    PASSWORD = "toor"  # [취약]
    DATABASE = "production"
