import hashlib
import os

def hash_password(password):
    """안전: PBKDF2-HMAC-SHA256을 사용한 강력한 해싱"""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        100000
    )
    return salt.hex() + ":" + key.hex()