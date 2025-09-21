from pydantic import BaseModel, EmailStr
from typing import Optional


# --- Pydantic Models ---


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


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str


class RefreshRequest(BaseModel):
    refresh_token: str



class UserDeleteRequest(BaseModel):
    password: str


