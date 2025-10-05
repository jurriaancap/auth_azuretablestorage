from pydantic import BaseModel, EmailStr


# --- Pydantic Models ---
# Response after registering MFA
class MFARegisterResponse(BaseModel):
    qr_base64: str
    provisioning_uri: str
    message: str = "MFA secret generated successfully. Please verify with your authenticator app."

# Request to setup MFA (requires password re-authentication)
class MFARegisterRequest(BaseModel):
    password: str  # User must re-enter password for security

# Request to verify MFA code during setup
class MFAVerifyRequest(BaseModel):
    password: str  # Password required for encryption/decryption
    secret: str    # Secret from registration response
    code: str      # TOTP code from authenticator app

# Request to validate MFA for existing users
class MFAValidateRequest(BaseModel):
    password: str  # Password required to decrypt stored secret
    code: str      # TOTP code from authenticator app

# Response after successful verification
class MFAVerifyResponse(BaseModel):
    message: str = "MFA verified successfully"

class UserBase(BaseModel):
    email: EmailStr
    password: str
    is_deleted: bool
    last_active_at: str
    created_at: str
    failed_login_attempts: int
    display_name: str
    profile_picture_url: str


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str
    code: str | None = None ## 


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str


class RefreshRequest(BaseModel):
    refresh_token: str


class UserDeleteRequest(BaseModel):
    password: str


