#!/usr/bin/env python3
"""
암호화 키 생성 스크립트 (scripts/generate_encryption_key.py)

32바이트 암호학적 안전 랜덤 키를 base64로 인코딩하여 출력합니다.
생성된 키를 .env 파일의 DALLO_ENCRYPTION_KEY에 설정하세요.

사용법:
    python scripts/generate_encryption_key.py
"""

import secrets
import base64


def generate_key() -> str:
    """32바이트(256비트) 암호학적 안전 랜덤 키를 생성합니다."""
    raw_key = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw_key).decode("ascii")


if __name__ == "__main__":
    key = generate_key()
    print("=" * 60)
    print("  Dallo DevSecOps - 암호화 키 생성기")
    print("=" * 60)
    print()
    print(f"  DALLO_ENCRYPTION_KEY={key}")
    print()
    print("  위 값을 .env 파일에 추가하세요.")
    print("  이 키를 소스 코드에 하드코딩하지 마세요!")
    print("=" * 60)
