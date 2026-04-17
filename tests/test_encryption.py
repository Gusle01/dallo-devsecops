"""
암호화 모듈 테스트 (tests/test_encryption.py)

- 환경변수 미설정 시 RuntimeError 발생 (fail-fast)
- 정상 암복호화
- 빈 문자열 처리
- 다른 키로 복호화 시 실패
"""

import os
import pytest

# 테스트 전에 환경변수 정리
_original_keys = {}


def _clear_encryption_env():
    """테스트용: 암호화 관련 환경변수 임시 제거"""
    for var in ("DALLO_ENCRYPTION_KEY", "ENCRYPTION_KEY"):
        _original_keys[var] = os.environ.pop(var, None)


def _restore_encryption_env():
    """테스트 후: 환경변수 복원"""
    for var, val in _original_keys.items():
        if val is not None:
            os.environ[var] = val
        else:
            os.environ.pop(var, None)


class TestEncryptionFailFast:
    """환경변수 미설정 시 앱 시작이 중단되는지 검증"""

    def test_missing_key_raises_runtime_error(self):
        _clear_encryption_env()
        try:
            # 모듈 캐시를 우회하기 위해 직접 함수 호출
            from shared.encryption import _load_encryption_key
            with pytest.raises(RuntimeError, match="암호화 키가 설정되지 않았습니다"):
                _load_encryption_key()
        finally:
            _restore_encryption_env()

    def test_missing_key_encryptor_raises(self):
        _clear_encryption_env()
        try:
            from shared.encryption import CodeEncryptor
            with pytest.raises(RuntimeError):
                CodeEncryptor()
        finally:
            _restore_encryption_env()


class TestEncryptDecrypt:
    """정상 암복호화 동작 검증"""

    def test_roundtrip(self):
        from shared.encryption import CodeEncryptor
        enc = CodeEncryptor(key="test-key-for-unit-tests")
        plaintext = "SELECT * FROM users WHERE id = ?"
        encrypted = enc.encrypt(plaintext)
        assert encrypted != plaintext
        assert enc.decrypt(encrypted) == plaintext

    def test_empty_string(self):
        from shared.encryption import CodeEncryptor
        enc = CodeEncryptor(key="test-key-for-unit-tests")
        assert enc.encrypt("") == ""
        assert enc.decrypt("") == ""

    def test_unicode_roundtrip(self):
        from shared.encryption import CodeEncryptor
        enc = CodeEncryptor(key="test-key-for-unit-tests")
        plaintext = "한글 코드 # 주석 포함 🔒"
        assert enc.decrypt(enc.encrypt(plaintext)) == plaintext

    def test_different_key_cannot_decrypt(self):
        from shared.encryption import CodeEncryptor
        enc1 = CodeEncryptor(key="key-alpha")
        enc2 = CodeEncryptor(key="key-beta")
        encrypted = enc1.encrypt("secret data")
        with pytest.raises(Exception):
            enc2.decrypt(encrypted)

    def test_is_encrypted(self):
        from shared.encryption import CodeEncryptor
        enc = CodeEncryptor(key="test-key-for-unit-tests")
        encrypted = enc.encrypt("test data")
        assert enc.is_encrypted(encrypted) is True
        assert enc.is_encrypted("plain text") is False


class TestKeyProvider:
    """KeyProvider 추상화 테스트"""

    def test_env_key_provider(self):
        os.environ["DALLO_ENCRYPTION_KEY"] = "test-provider-key"
        try:
            from db.key_provider import EnvKeyProvider
            provider = EnvKeyProvider()
            assert provider.get_key() == "test-provider-key"
        finally:
            _restore_encryption_env()

    def test_env_key_provider_missing(self):
        _clear_encryption_env()
        try:
            from db.key_provider import EnvKeyProvider
            provider = EnvKeyProvider()
            with pytest.raises(RuntimeError):
                provider.get_key()
        finally:
            _restore_encryption_env()

    def test_fallback_to_legacy_var(self):
        _clear_encryption_env()
        os.environ["ENCRYPTION_KEY"] = "legacy-fallback"
        try:
            from db.key_provider import EnvKeyProvider
            provider = EnvKeyProvider()
            assert provider.get_key() == "legacy-fallback"
        finally:
            os.environ.pop("ENCRYPTION_KEY", None)
            _restore_encryption_env()
