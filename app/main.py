from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import FastAPI, Header, HTTPException

from .models import (
    ErrorResponse,
    MfaRequiredResponse,
    StartAuthRequest,
    TokenResponse,
)
from .tesla_sso import LoginResult, start_login

app = FastAPI(title="tesla-broker", version="0.2.0")

BROKER_SHARED_SECRET = os.getenv("BROKER_SHARED_SECRET")


def _check_secret(x_broker_secret: str | None) -> None:
    if not BROKER_SHARED_SECRET:
        return
    if not x_broker_secret or x_broker_secret != BROKER_SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True}


@app.post(
    "/auth/start",
    response_model=TokenResponse | MfaRequiredResponse,
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
)
def auth_start(payload: StartAuthRequest, x_broker_secret: str | None = Header(default=None)):
    """
    Perform Tesla SSO login using full browser automation.
    
    This approach lets the browser handle all JS challenges, Captcha, etc.
    We automate form filling and wait for the callback URL.
    
    If MFA is required and passcode/backup_code is not provided,
    returns MFA_REQUIRED status. Client should retry with passcode.
    """
    _check_secret(x_broker_secret)

    try:
        result: LoginResult = start_login(
            payload.email,
            payload.password,
            locale=payload.locale,
            passcode=payload.passcode,
            backup_code=payload.backup_code,
        )

        return TokenResponse(
            access_token=result.access_token,
            refresh_token=result.refresh_token,
            expires_in=result.expires_in,
        )

    except ValueError as e:
        error_msg = str(e)
        
        # Special case: MFA required
        if error_msg == "MFA_REQUIRED":
            return MfaRequiredResponse(
                flow_id="browser-session",
                transaction_id="browser-session",
                factors=[],
            )
        
        raise HTTPException(status_code=400, detail=error_msg)
    
    except HTTPException:
        raise
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# Note: In full-browser mode, MFA is handled in a single request by passing
# passcode/backup_code to /auth/start. The /auth/mfa/verify endpoint is
# kept for backwards compatibility but simply asks user to retry /auth/start
# with the passcode included.

@app.post(
    "/auth/mfa/verify",
    response_model=TokenResponse,
    responses={400: {"model": ErrorResponse}},
)
def auth_mfa_verify(payload: dict, x_broker_secret: str | None = Header(default=None)):
    """
    In full-browser mode, MFA must be handled in a single session.
    Please retry /auth/start with passcode or backup_code included.
    """
    _check_secret(x_broker_secret)
    raise HTTPException(
        status_code=400,
        detail="In browser mode, please include passcode in /auth/start request instead"
    )
