from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, EmailStr, Field


class StartAuthRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)
    device: str = Field(default="1", pattern="^[12]$")
    locale: str = Field(default="zh-CN")

    # MFA codes - in browser mode, include these if MFA is required
    passcode: Optional[str] = None
    backup_code: Optional[str] = None


class VerifyMfaRequest(BaseModel):
    flow_id: str
    factor_id: Optional[str] = None
    passcode: Optional[str] = None
    backup_code: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None


class MfaFactor(BaseModel):
    id: str
    name: str
    factorType: Optional[str] = None
    factorProvider: Optional[str] = None


class MfaRequiredResponse(BaseModel):
    status: Literal["MFA_REQUIRED"] = "MFA_REQUIRED"
    flow_id: str
    transaction_id: str
    factors: list[MfaFactor] = []


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[Any] = None
