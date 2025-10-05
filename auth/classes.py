from pydantic import BaseModel, EmailStr, field_validator
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
    password: str

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        """
        Validate password meets security requirements:
        - 8-128 characters (NIST recommended range)
        - At least one uppercase letter
        - At least one lowercase letter  
        - At least one digit
        - At least one special character
        """
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if len(v) > 128:
            raise ValueError('Password must be no more than 128 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain at least one special character (!@#$%^&*(),.?":{}|<>)')
        return v

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        """
        Additional email validation beyond EmailStr
        """
        email_str = str(v)
        if len(email_str) > 254:  # RFC 5321 limit
            raise ValueError('Email address is too long (max 254 characters)')
        if '..' in email_str:
            raise ValueError('Email address cannot contain consecutive dots')
        return v


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
    new_password: str

    @field_validator('new_password')
    @classmethod
    def validate_new_password(cls, v):
        """
        Validate new password meets security requirements:
        - 8-128 characters (NIST recommended range)
        - At least one uppercase letter
        - At least one lowercase letter  
        - At least one digit
        - At least one special character
        """
        if len(v) < 8:
            raise ValueError('New password must be at least 8 characters long')
        if len(v) > 128:
            raise ValueError('New password must be no more than 128 characters long')
        if not re.search(r'[A-Z]', v):
            raise ValueError('New password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('New password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('New password must contain at least one digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('New password must contain at least one special character (!@#$%^&*(),.?":{}|<>)')
        return v


