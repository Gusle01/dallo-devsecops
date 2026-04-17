"""
암호화 키 제공자 추상화 (db/key_provider.py)

현재는 환경변수 기반(EnvKeyProvider)만 구현.
향후 AWS KMS, HashiCorp Vault 등 전용 키 관리 서비스로 교체 가능하도록
추상 인터페이스를 정의합니다.

사용법:
    from db.key_provider import get_key_provider
    provider = get_key_provider()
    key = provider.get_key()
"""

import os
from abc import ABC, abstractmethod


class KeyProvider(ABC):
    """암호화 키를 제공하는 추상 인터페이스"""

    @abstractmethod
    def get_key(self) -> str:
        """암호화 키를 반환합니다.

        Returns:
            암호화에 사용할 시크릿 문자열

        Raises:
            RuntimeError: 키를 가져올 수 없을 때
        """
        ...


class EnvKeyProvider(KeyProvider):
    """환경변수에서 암호화 키를 로드하는 제공자"""

    def __init__(self, env_var: str = "DALLO_ENCRYPTION_KEY",
                 fallback_var: str = "ENCRYPTION_KEY"):
        self._env_var = env_var
        self._fallback_var = fallback_var

    def get_key(self) -> str:
        key = os.environ.get(self._env_var) or os.environ.get(self._fallback_var)
        if not key:
            raise RuntimeError(
                f"[SECURITY] 환경변수 {self._env_var}가 설정되지 않았습니다. "
                f"키 생성: python scripts/generate_encryption_key.py"
            )
        return key


# 향후 구현 예시:
# class VaultKeyProvider(KeyProvider):
#     """HashiCorp Vault에서 암호화 키를 로드하는 제공자"""
#     def __init__(self, vault_addr: str, secret_path: str):
#         self._vault_addr = vault_addr
#         self._secret_path = secret_path
#     def get_key(self) -> str:
#         # hvac 라이브러리를 사용하여 Vault에서 키 조회
#         raise NotImplementedError("Vault 연동은 추후 구현 예정")


def get_key_provider() -> KeyProvider:
    """설정에 따라 적절한 KeyProvider를 반환합니다.

    현재는 EnvKeyProvider만 지원. 향후 DALLO_KEY_PROVIDER 환경변수로
    'vault', 'kms' 등을 지정하여 교체 가능.
    """
    provider_type = os.environ.get("DALLO_KEY_PROVIDER", "env").lower()
    if provider_type == "env":
        return EnvKeyProvider()
    # elif provider_type == "vault":
    #     return VaultKeyProvider(
    #         vault_addr=os.environ["VAULT_ADDR"],
    #         secret_path=os.environ.get("VAULT_SECRET_PATH", "secret/dallo/encryption")
    #     )
    else:
        raise ValueError(f"지원하지 않는 키 제공자: {provider_type}")
