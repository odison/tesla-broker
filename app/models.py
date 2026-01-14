from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, Field


class StartAuthRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)
    locale: str = Field(default="zh-CN")
    
    # Optional MFA codes (can be included in first request)
    passcode: Optional[str] = None
    backup_code: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None


class MfaRequiredResponse(BaseModel):
    status: Literal["MFA_REQUIRED"] = "MFA_REQUIRED"
    message: str = "MFA is required. Please include passcode in the request."


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
