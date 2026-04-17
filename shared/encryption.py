"""
AES-256 암호화 모듈 (shared/encryption.py)

DB에 저장되는 코드 스니펫을 AES-256으로 암호화/복호화합니다.
암호화 키는 반드시 환경변수로 제공해야 합니다. (하드코딩 금지)

사용법:
    from shared.encryption import CodeEncryptor

    encryptor = CodeEncryptor()  # DALLO_ENCRYPTION_KEY 환경변수에서 키 로드
    encrypted = encryptor.encrypt("sensitive code here")
    decrypted = encryptor.decrypt(encrypted)
"""

import os
import base64
import hashlib
import logging
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)


def _derive_key(secret: str) -> bytes:
    """문자열 시크릿에서 Fernet 호환 키(32바이트 base64)를 유도합니다."""
    key_bytes = hashlib.sha256(secret.encode()).digest()
    return base64.urlsafe_b64encode(key_bytes)


def _load_encryption_key() -> str:
    """환경변수에서 암호화 키를 로드합니다. 미설정 시 앱 시작을 중단합니다."""
    # DALLO_ENCRYPTION_KEY 우선, 기존 ENCRYPTION_KEY도 호환 지원
    key = os.environ.get("DALLO_ENCRYPTION_KEY") or os.environ.get("ENCRYPTION_KEY")
    if not key:
        raise RuntimeError(
            "[SECURITY] 암호화 키가 설정되지 않았습니다. "
            "환경변수 DALLO_ENCRYPTION_KEY를 설정하세요.\n"
            "키 생성: python scripts/generate_encryption_key.py"
        )
    return key


class CodeEncryptor:
    """AES-256 기반 코드 스니펫 암호화/복호화"""

    def __init__(self, key: str = None):
        """
        Args:
            key: 암호화 키 (없으면 DALLO_ENCRYPTION_KEY 환경변수에서 로드)

        Raises:
            RuntimeError: 키가 제공되지 않고 환경변수도 미설정일 때
        """
        secret = key or _load_encryption_key()
        self._fernet = Fernet(_derive_key(secret))

    def encrypt(self, plaintext: str) -> str:
        """
        문자열을 AES-256으로 암호화합니다.

        Args:
            plaintext: 평문

        Returns:
            base64 인코딩된 암호문
        """
        if not plaintext:
            return ""
        encrypted = self._fernet.encrypt(plaintext.encode("utf-8"))
        return encrypted.decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """
        암호문을 복호화합니다.

        Args:
            ciphertext: encrypt()로 생성된 암호문

        Returns:
            원본 평문
        """
        if not ciphertext:
            return ""
        decrypted = self._fernet.decrypt(ciphertext.encode("utf-8"))
        return decrypted.decode("utf-8")

    def is_encrypted(self, text: str) -> bool:
        """텍스트가 암호화된 상태인지 확인합니다."""
        try:
            self._fernet.decrypt(text.encode("utf-8"))
            return True
        except Exception:
            return False
