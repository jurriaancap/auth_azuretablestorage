import base64
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

import jwt
from datetime import datetime, timedelta, timezone

from auth.config import JWT_SECRET, JWT_ALGORITHM


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    return PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=100_000)  # type: ignore


def encrypt_with_key(key: bytes, plain_text: str) -> tuple[str, str, str]:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode("utf-8"))
    return b64e(cipher.nonce), b64e(ciphertext), b64e(tag)


def decrypt_with_key(
    key: bytes, b64_nonce: str, b64_ciphertext: str, b64_tag: str
) -> str:
    nonce = b64d(b64_nonce)
    ciphertext = b64d(b64_ciphertext)
    tag = b64d(b64_tag)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")


def create_jwt_token(data: dict, exp_minutes: int) -> str:
    payload = {
        **data,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=exp_minutes),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
