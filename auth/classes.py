from pydantic import BaseModel, EmailStr, field_validator, Field
import re


# --- Pydantic Models ---
# Response after registering MFA
class MFARegisterResponse(BaseModel):
    qr_base64: str
    provisioning_uri: str
    message: str = "MFA secret generated successfully. Please verify with your authenticator app."

class MFARegisterRequest(BaseModel):
    password: str  # User must re-enter password for security

class MFAVerifyRequest(BaseModel):
    password: str  # Password required for encryption/decryption
    secret: str    # Secret from registration response
    code: str      # TOTP code from authenticator app

    @field_validator('code')
    @classmethod
    def validate_totp_code(cls, v):
        """Validate TOTP code format"""
        if not re.match(r'^\d{6}$', v):
            raise ValueError('TOTP code must be exactly 6 digits')
        return v

class MFAValidateRequest(BaseModel):
    password: str  # Password required to decrypt stored secret
    code: str      # TOTP code from authenticator app

    @field_validator('code')
    @classmethod
    def validate_totp_code(cls, v):
        """Validate TOTP code format"""
        if not re.match(r'^\d{6}$', v):
            raise ValueError('TOTP code must be exactly 6 digits')
        return v

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
    password: str = Field(min_length=8, max_length=128)

    @field_validator('password')
    @classmethod
    def validate_password_complexity(cls, v):
        """Validate password meets all security requirements."""
        if (len(v) >= 8 and len(v) <= 128 and 
            re.search(r'[A-Z]', v) and 
            re.search(r'[a-z]', v) and 
            re.search(r'\d', v) and 
            re.search(r'[!@#$%^&*(),.?":{}|<>]', v)):
            return v
        
        raise ValueError(
            "Password must contain at least one uppercase letter, one lowercase letter, "
            "one digit, one special character (!@#$%^&*(),.?\":{}|<>), and be between 8-128 characters long."
        )


class UserLogin(BaseModel):
    email: EmailStr
    password: str
    code: str | None = None

    @field_validator('code')
    @classmethod
    def validate_totp_code(cls, v):
        """Validate TOTP code format if provided"""
        if v is not None and not re.match(r'^\d{6}$', v):
            raise ValueError('TOTP code must be exactly 6 digits')
        return v


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    mfa_required: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str


class UserDeleteRequest(BaseModel):
    password: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator('new_password')
    @classmethod
    def validate_new_password_complexity(cls, v):
        """Validate new password meets all security requirements."""
        if (len(v) >= 8 and len(v) <= 128 and 
            re.search(r'[A-Z]', v) and 
            re.search(r'[a-z]', v) and 
            re.search(r'\d', v) and 
            re.search(r'[!@#$%^&*(),.?":{}|<>]', v)):
            return v
        
        raise ValueError(
            "New password must contain at least one uppercase letter, one lowercase letter, "
            "one digit, one special character (!@#$%^&*(),.?\":{}|<>), and be between 8-128 characters long."
        )


