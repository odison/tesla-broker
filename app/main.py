from __future__ import annotations

import logging
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

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Tesla Token Broker",
    version="0.3.0",
    description="Internal service for Tesla SSO token acquisition using Playwright"
)

BROKER_SHARED_SECRET = os.getenv("BROKER_SHARED_SECRET")


def _check_secret(x_broker_secret: str | None) -> None:
    if not BROKER_SHARED_SECRET:
        return
    if not x_broker_secret or x_broker_secret != BROKER_SHARED_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/health")
def health() -> Dict[str, Any]:
    logger.info("Health check requested")
    return {"ok": True, "version": "0.3.0", "engine": "playwright"}


@app.post(
    "/auth/start",
    response_model=TokenResponse | MfaRequiredResponse,
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
)
def auth_start(payload: StartAuthRequest, x_broker_secret: str | None = Header(default=None)):
    """
    Perform Tesla SSO login using Playwright browser automation.
    
    This approach uses Playwright which has better anti-bot detection bypass.
    
    If MFA is required:
    - If passcode/backup_code is not provided, returns MFA_REQUIRED status
    - If passcode/backup_code is provided, attempts to complete MFA
    
    Args:
        email: Tesla account email
        password: Tesla account password
        locale: Locale for the login page (default: zh-CN)
        passcode: MFA passcode from authenticator app (optional)
        backup_code: MFA backup code (optional)
    
    Returns:
        TokenResponse with access_token, refresh_token, and expires_in
        OR MfaRequiredResponse if MFA is needed
    """
    logger.info(f"=== Auth start request received ===")
    logger.info(f"Email: {payload.email[:3]}***")
    logger.info(f"Locale: {payload.locale}")
    logger.info(f"Has passcode: {bool(payload.passcode)}")
    logger.info(f"Has backup_code: {bool(payload.backup_code)}")
    
    _check_secret(x_broker_secret)

    try:
        logger.info("Calling start_login...")
        result: LoginResult = start_login(
            payload.email,
            payload.password,
            locale=payload.locale,
            passcode=payload.passcode,
            backup_code=payload.backup_code,
        )

        logger.info("Login successful, returning tokens")
        return TokenResponse(
            access_token=result.access_token,
            refresh_token=result.refresh_token,
            expires_in=result.expires_in,
        )

    except ValueError as e:
        error_msg = str(e)
        logger.warning(f"ValueError: {error_msg}")
        
        # Special case: MFA required
        if error_msg == "MFA_REQUIRED":
            logger.info("MFA required, returning MFA_REQUIRED response")
            return MfaRequiredResponse()

        if error_msg == "AKAMAI_CHALLENGE":
            raise HTTPException(
                status_code=400,
                detail="Akamai Challenge triggered (curl/headless likely blocked). Try PLAYWRIGHT_HEADLESS=false on a machine with GUI, or change egress IP.",
            )
        
        raise HTTPException(status_code=400, detail=error_msg)
    
    except HTTPException:
        raise
    
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
