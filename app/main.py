from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import FastAPI, Header, HTTPException

from .flow_store import FlowState, FlowStore
from .models import (
    ErrorResponse,
    MfaFactor,
    MfaRequiredResponse,
    StartAuthRequest,
    TokenResponse,
    VerifyMfaRequest,
)
from .tesla_sso import finish_and_exchange_token, get_mfa_factors, start_login, verify_mfa

app = FastAPI(title="tesla-broker", version="0.1.0")

BROKER_SHARED_SECRET = os.getenv("BROKER_SHARED_SECRET")
store = FlowStore(
    maxsize=int(os.getenv("BROKER_FLOW_MAXSIZE", "1024")),
    ttl_seconds=int(os.getenv("BROKER_FLOW_TTL_SECONDS", "600")),
)


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
    _check_secret(x_broker_secret)

    try:
        start = start_login(payload.email, payload.password, locale=payload.locale)

        if start.status == "OK":
            access_token, refresh_token = finish_and_exchange_token(
                start.session,
                params=start.params,
                code_verifier=start.code_verifier,
                transaction_id=start.transaction_id,
            )
            return TokenResponse(access_token=access_token, refresh_token=refresh_token)

        # MFA required
        factors_raw = get_mfa_factors(start.session, start.transaction_id)
        factors = [
            MfaFactor(
                id=f.get("id"),
                name=f.get("name"),
                factorType=f.get("factorType"),
                factorProvider=f.get("factorProvider"),
            )
            for f in factors_raw
            if f.get("id") and f.get("name")
        ]

        # If client provided MFA codes in one shot, try to finish immediately
        if payload.passcode or payload.backup_code:
            factor_id = None
            if payload.passcode:
                device_name = f"Device #{payload.device}"
                matched = [f for f in factors_raw if f.get("name") == device_name]
                if matched:
                    factor_id = matched[0].get("id")
                elif len(factors_raw) == 1:
                    factor_id = factors_raw[0].get("id")
                else:
                    factor_id = factors_raw[0].get("id") if factors_raw else None

            verify_mfa(
                start.session,
                transaction_id=start.transaction_id,
                factor_id=factor_id,
                passcode=payload.passcode,
                backup_code=payload.backup_code,
            )

            access_token, refresh_token = finish_and_exchange_token(
                start.session,
                params=start.params,
                code_verifier=start.code_verifier,
                transaction_id=start.transaction_id,
            )
            return TokenResponse(access_token=access_token, refresh_token=refresh_token)

        flow_id = store.create(
            FlowState(
                cookies={c.name: c.value for c in start.session.cookies},
                params=start.params,
                code_verifier=start.code_verifier,
                transaction_id=start.transaction_id,
                locale=payload.locale,
            )
        )

        return MfaRequiredResponse(flow_id=flow_id, transaction_id=start.transaction_id, factors=factors)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post(
    "/auth/mfa/verify",
    response_model=TokenResponse,
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
)
def auth_mfa_verify(payload: VerifyMfaRequest, x_broker_secret: str | None = Header(default=None)):
    _check_secret(x_broker_secret)

    flow = store.get(payload.flow_id)
    if not flow:
        raise HTTPException(status_code=400, detail="Invalid or expired flow_id")

    try:
        import requests

        session = requests.Session()
        for k, v in flow.cookies.items():
            session.cookies.set(k, v)

        verify_mfa(
            session,
            transaction_id=flow.transaction_id,
            factor_id=payload.factor_id,
            passcode=payload.passcode,
            backup_code=payload.backup_code,
        )

        access_token, refresh_token = finish_and_exchange_token(
            session,
            params=flow.params,
            code_verifier=flow.code_verifier,
            transaction_id=flow.transaction_id,
        )

        store.delete(payload.flow_id)
        return TokenResponse(access_token=access_token, refresh_token=refresh_token)

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
