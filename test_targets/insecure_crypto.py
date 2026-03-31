"""
취약한 암호화 방식 샘플 코드
- Bandit 탐지 대상: B303 (md5/sha1), B311 (random), B324 (hashlib)
- OWASP: A02:2021 Cryptographic Failures
"""

import hashlib
import random
import string
import tempfile


def hash_password_md5(password: str) -> str:
    """취약: MD5는 비밀번호 해싱에 부적합 (충돌 공격 가능)"""
    # [취약] MD5 사용
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password: str) -> str:
    """취약: SHA-1도 비밀번호 해싱에 부적합"""
    # [취약] SHA-1 사용
    return hashlib.sha1(password.encode()).hexdigest()


def generate_session_id() -> str:
    """취약: random 모듈은 암호학적으로 안전하지 않음"""
    # [취약] random.choice 사용 (예측 가능)
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(32))


def generate_otp() -> str:
    """취약: OTP 생성에 random 사용"""
    # [취약] random.randint는 암호학적으로 안전하지 않음
    return str(random.randint(100000, 999999))


def create_temp_file(data: str) -> str:
    """취약: 안전하지 않은 임시 파일 생성"""
    # [취약] mktemp는 race condition 취약
    filename = tempfile.mktemp(suffix=".txt")
    with open(filename, "w") as f:
        f.write(data)
    return filename


def simple_encrypt(text: str, key: int) -> str:
    """취약: 시저 암호 같은 자체 구현 암호화"""
    # [취약] 자체 암호화 구현 (보안성 없음)
    result = ""
    for char in text:
        result += chr(ord(char) + key)
    return result
