import pyotp
import qrcode
import qrcode.image.pil
from io import BytesIO
from base64 import b64encode
from typing import Tuple
from auth.helpers import derive_key_from_password, encrypt_with_key, decrypt_with_key


def generate_totp_secret() -> str:
    """Return a new random base32 TOTP secret."""
    return pyotp.random_base32()


def create_provisioning_uri(secret: str, account_name: str, issuer: str = "MyApp") -> str:
    """
    Return the otpauth provisioning URI for an authenticator app.
    example : 
        issuer="authentication app"
        account_name="email@example.com"
    """
    return pyotp.totp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=issuer)


def generate_qr_image_bytes(secret: str, account_name: str, issuer: str = "MyApp") -> BytesIO:
    """
    Return a BytesIO containing a PNG QR code for the provisioning URI.
    Use StreamingResponse(qr_bytes, media_type="image/png") in FastAPI.
    """
    uri = create_provisioning_uri(secret, account_name, issuer)
    qr = qrcode.QRCode()
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(image_factory=qrcode.image.pil.PilImage)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


def generate_qr_base64(secret: str, account_name: str, issuer: str = "MyApp") -> Tuple[str, str]:
    """
    Return (base64_png, provisioning_uri). Useful if you want JSON with an embedded image.
    """
    buf = generate_qr_image_bytes(secret, account_name, issuer)
    b64 = b64encode(buf.getvalue()).decode("ascii")
    uri = create_provisioning_uri(secret, account_name, issuer)
    return b64, uri


def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verify a TOTP code against the secret.
    Returns True if the code is valid, False otherwise.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code)


def encrypt_totp_secret_with_password(secret: str, password: str, email: str) -> str:
    """Encrypt a TOTP secret using the user's password"""
    # Use email as salt (unique per user)
    salt = email.encode('utf-8')[:16].ljust(16, b'0')  # Ensure 16 bytes
    key = derive_key_from_password(password, salt)
    nonce, ciphertext, tag = encrypt_with_key(key, secret)
    # Store as "nonce:ciphertext:tag" format
    return f"{nonce}:{ciphertext}:{tag}"


def decrypt_totp_secret_with_password(encrypted_secret: str, password: str, email: str) -> str:
    """Decrypt a TOTP secret using the user's password"""
    try:
        nonce, ciphertext, tag = encrypted_secret.split(":")
        # Use email as salt (same as encryption)
        salt = email.encode('utf-8')[:16].ljust(16, b'0')  # Ensure 16 bytes
        key = derive_key_from_password(password, salt)
        return decrypt_with_key(key, nonce, ciphertext, tag)
    except Exception as e:
        raise ValueError(f"Failed to decrypt TOTP secret: {e}")


