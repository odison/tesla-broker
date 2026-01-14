from __future__ import annotations

import base64
import hashlib
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

MAX_ATTEMPTS = int(os.getenv("TESLA_MAX_ATTEMPTS", "7"))

UA = os.getenv("TESLA_UA", "UA")
X_TESLA_USER_AGENT = os.getenv("TESLA_X_TESLA_USER_AGENT", "UA")

AUTHORIZE_URL = os.getenv("TESLA_AUTHORIZE_URL", "https://auth.tesla.cn/oauth2/v3/authorize")
TOKEN_URL = os.getenv("TESLA_TOKEN_URL", "https://auth.tesla.cn/oauth2/v3/token")
REDIRECT_URI = os.getenv("TESLA_REDIRECT_URI", "https://auth.tesla.com/void/callback")
CLIENT_ID = os.getenv("TESLA_CLIENT_ID", "ownerapi")


def gen_params() -> tuple[bytes, bytes, str]:
    verifier_bytes = os.urandom(86)
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=")
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier).digest()).rstrip(b"=")
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("utf-8")
    return code_verifier, code_challenge, state


def create_driver() -> webdriver.Chrome:
    options = webdriver.ChromeOptions()

    # Docker/headless defaults
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")

    chrome_bin = os.getenv("CHROME_BIN")
    if chrome_bin:
        options.binary_location = chrome_bin

    driver = webdriver.Chrome(options=options)
    try:
        driver.execute_cdp_cmd("Network.setUserAgentOverride", {"userAgent": UA})
    except Exception:
        # Not fatal; some drivers may not support CDP.
        pass
    return driver


@dataclass
class StartResult:
    status: str
    session: requests.Session
    params: list[tuple[str, str]]
    code_verifier: str
    transaction_id: str


def _initial_headers() -> Dict[str, str]:
    # Note: Tesla may trigger JS challenge if UA looks browser-like.
    # Keep this configurable; current default is a mobile UA for compatibility.
    return {
        "User-Agent": os.getenv(
            "TESLA_IDP_UA",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
        ),
    }


class NeedsBrowserFallback(Exception):
    """Raised when HTML doesn't contain expected fields and we need Selenium."""
    pass


def _extract_csrf_and_txid_from_html(html: str) -> tuple[str, str]:
    csrf_match = re.search(r'name="_csrf".+?value="([^"]+)"', html, re.DOTALL)
    txid_match = re.search(r'name="transaction_id".+?value="([^"]+)"', html, re.DOTALL)
    if not csrf_match or not txid_match:
        raise NeedsBrowserFallback("Could not extract csrf/transaction_id from HTML")
    return csrf_match.group(1), txid_match.group(1)


def _extract_csrf_and_txid_via_browser(url: str) -> tuple[str, str, Dict[str, str]]:
    driver = create_driver()
    try:
        driver.get(url)
        WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.CSS_SELECTOR, "input[name=identity]")))

        cookies = {c["name"]: c["value"] for c in driver.get_cookies()}
        csrf = driver.find_element(By.CSS_SELECTOR, "input[name=_csrf]").get_attribute("value")
        transaction_id = driver.find_element(By.CSS_SELECTOR, "input[name=transaction_id]").get_attribute("value")
        return csrf, transaction_id, cookies
    finally:
        driver.quit()


def _session_from_cookies(cookies: Dict[str, str]) -> requests.Session:
    s = requests.Session()
    for k, v in cookies.items():
        s.cookies.set(k, v)
    return s


def start_login(email: str, password: str, *, locale: str = "zh-CN") -> StartResult:
    headers = _initial_headers()

    code_verifier_b, code_challenge, state = gen_params()
    params: list[tuple[str, str]] = [
        ("client_id", CLIENT_ID),
        ("code_challenge", code_challenge.decode("utf-8")),
        ("code_challenge_method", "S256"),
        ("locale", locale),
        ("prompt", "login"),
        ("redirect_uri", REDIRECT_URI),
        ("response_type", "code"),
        ("scope", "openid email offline_access"),
        ("state", state),
    ]

    session = requests.Session()
    resp = session.get(AUTHORIZE_URL, headers=headers, params=params)

    # Try HTML extraction first; fallback to browser if it fails
    try:
        if "<title>" in resp.text:
            csrf, transaction_id = _extract_csrf_and_txid_from_html(resp.text)
        else:
            raise NeedsBrowserFallback("No <title> in response")
    except NeedsBrowserFallback:
        csrf, transaction_id, driver_cookies = _extract_csrf_and_txid_via_browser(resp.request.url)
        for k, v in driver_cookies.items():
            session.cookies.set(k, v)
    else:
        pass  # csrf/transaction_id already set

    # identity phase
    data = {
        "_csrf": csrf,
        "_phase": "identity",
        "transaction_id": transaction_id,
        "cancel": "",
        "identity": email,
    }

    resp = session.post(
        AUTHORIZE_URL,
        headers=headers,
        params=params,
        data=data,
        allow_redirects=False,
    )

    # Try HTML extraction first; fallback to browser if it fails
    try:
        if "<title>" in resp.text:
            csrf, transaction_id = _extract_csrf_and_txid_from_html(resp.text)
        else:
            raise NeedsBrowserFallback("No <title> in response after identity phase")
    except NeedsBrowserFallback:
        csrf, transaction_id, driver_cookies = _extract_csrf_and_txid_via_browser(resp.request.url)
        for k, v in driver_cookies.items():
            session.cookies.set(k, v)

    # authenticate phase
    data = {
        "_csrf": csrf,
        "_phase": "authenticate",
        "_process": "1",
        "transaction_id": transaction_id,
        "cancel": "",
        "identity": email,
        "credential": password,
        "privacy_consent": 1,
    }

    resp = None
    for attempt in range(MAX_ATTEMPTS):
        resp = session.post(
            AUTHORIZE_URL,
            headers=headers,
            params=params,
            data=data,
            allow_redirects=False,
        )

        if resp.status_code == 401 and "We could not sign you in" in resp.text:
            raise ValueError("Invalid credentials")

        if resp.ok and (resp.status_code == 302 or "<title>" in resp.text):
            break
        if resp.ok and resp.status_code == 200 and "/mfa/verify" in resp.text:
            break

        time.sleep(3)

    if resp is None:
        raise RuntimeError("No response from Tesla")

    is_mfa = bool(resp.status_code == 200 and "/mfa/verify" in resp.text)
    code_verifier = code_verifier_b.decode("utf-8")

    return StartResult(
        status="MFA_REQUIRED" if is_mfa else "OK",
        session=session,
        params=params,
        code_verifier=code_verifier,
        transaction_id=transaction_id,
    )


def get_mfa_factors(session: requests.Session, transaction_id: str) -> list[dict[str, Any]]:
    headers = _initial_headers()
    resp = session.get(
        f"{AUTHORIZE_URL}/mfa/factors?transaction_id={transaction_id}",
        headers=headers,
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("data", [])


def verify_mfa(
    session: requests.Session,
    *,
    transaction_id: str,
    factor_id: Optional[str],
    passcode: Optional[str],
    backup_code: Optional[str],
) -> None:
    headers = _initial_headers()

    if passcode:
        if not factor_id:
            raise ValueError("factor_id is required when using passcode")
        payload = {"transaction_id": transaction_id, "factor_id": factor_id, "passcode": passcode}
        resp = session.post(f"{AUTHORIZE_URL}/mfa/verify", headers=headers, json=payload)
        resp.raise_for_status()
        body = resp.json().get("data", {})
        if not body.get("approved") or not body.get("valid"):
            raise ValueError("Invalid passcode")
        return

    if backup_code:
        payload = {"transaction_id": transaction_id, "backup_code": backup_code}
        resp = session.post(f"{AUTHORIZE_URL}/mfa/backupcodes/attempt", headers=headers, json=payload)
        resp.raise_for_status()
        body = resp.json().get("data", {})
        if not body.get("valid"):
            raise ValueError("Invalid backup code")
        return

    raise ValueError("Either passcode or backup_code is required")


def finish_and_exchange_token(
    session: requests.Session,
    *,
    params: list[tuple[str, str]],
    code_verifier: str,
    transaction_id: str,
) -> tuple[str, str]:
    headers = _initial_headers()

    # Ask authorize endpoint to redirect with code
    data = {"transaction_id": transaction_id}
    resp = None
    for _ in range(MAX_ATTEMPTS):
        resp = session.post(AUTHORIZE_URL, headers=headers, params=params, data=data, allow_redirects=False)
        if resp.headers.get("location"):
            break
        time.sleep(1)

    if resp is None or not resp.headers.get("location"):
        raise ValueError("Did not receive redirect location")

    location = resp.headers["location"]
    parsed = urlparse(location)
    q = parse_qs(parsed.query)
    if "code" not in q or not q["code"]:
        raise ValueError("Missing authorization code")

    code = q["code"][0]

    token_headers = {"user-agent": UA, "x-tesla-user-agent": X_TESLA_USER_AGENT}
    payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code_verifier": code_verifier,
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }

    token_resp = session.post(TOKEN_URL, headers=token_headers, json=payload)
    token_resp.raise_for_status()
    body = token_resp.json()
    return body["access_token"], body["refresh_token"]
