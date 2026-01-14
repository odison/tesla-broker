"""
Tesla SSO automation using full browser approach.

Inspired by https://github.com/adriankumpf/tesla_auth

Instead of mixing requests + Selenium with HTML parsing,
we let the browser handle everything (JS challenges, Captcha, etc.)
and just automate form filling + monitor URL for the callback.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from selenium import webdriver
from selenium.common.exceptions import (
    NoSuchElementException,
    TimeoutException,
)
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

# Configuration
MAX_WAIT_SECONDS = int(os.getenv("TESLA_MAX_WAIT_SECONDS", "60"))
POLL_INTERVAL = float(os.getenv("TESLA_POLL_INTERVAL", "0.5"))

CLIENT_ID = os.getenv("TESLA_CLIENT_ID", "ownerapi")
AUTH_URL = os.getenv("TESLA_AUTHORIZE_URL", "https://auth.tesla.com/oauth2/v3/authorize")
TOKEN_URL = os.getenv("TESLA_TOKEN_URL", "https://auth.tesla.com/oauth2/v3/token")
TOKEN_URL_CN = os.getenv("TESLA_TOKEN_URL_CN", "https://auth.tesla.cn/oauth2/v3/token")
REDIRECT_URI = os.getenv("TESLA_REDIRECT_URI", "https://auth.tesla.com/void/callback")

# Scopes
SCOPES = "openid email offline_access"


def _generate_pkce() -> tuple[str, str, str]:
    """Generate PKCE code_verifier, code_challenge, and state."""
    verifier_bytes = os.urandom(32)
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=").decode("utf-8")
    
    challenge_bytes = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(challenge_bytes).rstrip(b"=").decode("utf-8")
    
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("utf-8")
    
    return code_verifier, code_challenge, state


def _build_authorize_url(code_challenge: str, state: str, locale: str = "zh-CN") -> str:
    """Build the Tesla OAuth2 authorize URL."""
    params = {
        "client_id": CLIENT_ID,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPES,
        "state": state,
        "locale": locale,
        "prompt": "login",
    }
    return f"{AUTH_URL}?{urlencode(params)}"


def _create_driver() -> webdriver.Chrome:
    """Create a headless Chrome driver."""
    options = webdriver.ChromeOptions()
    
    # Headless mode
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    
    # Avoid detection
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)
    
    chrome_bin = os.getenv("CHROME_BIN")
    if chrome_bin:
        options.binary_location = chrome_bin
    
    driver = webdriver.Chrome(options=options)
    
    # Remove webdriver property to avoid detection
    driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
    
    return driver


def _is_callback_url(url: str) -> bool:
    """Check if the URL is the OAuth callback URL."""
    return url.startswith(REDIRECT_URI)


def _extract_code_from_url(url: str) -> tuple[str, str, Optional[str]]:
    """Extract code, state, and issuer from callback URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if "error" in params:
        error = params["error"][0]
        if error == "login_cancelled":
            raise ValueError("Login was cancelled by user")
        raise ValueError(f"OAuth error: {error}")
    
    if "code" not in params:
        raise ValueError("No authorization code in callback URL")
    
    code = params["code"][0]
    state = params.get("state", [""])[0]
    issuer = params.get("issuer", [None])[0]
    
    return code, state, issuer


def _exchange_code_for_token(code: str, code_verifier: str, issuer: Optional[str] = None) -> tuple[str, str, int]:
    """Exchange authorization code for access/refresh tokens."""
    # Use CN token URL if issuer is from China
    if issuer and "tesla.cn" in issuer:
        token_url = TOKEN_URL_CN
    else:
        token_url = TOKEN_URL
    
    payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "code_verifier": code_verifier,
        "redirect_uri": REDIRECT_URI,
    }
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    
    resp = requests.post(token_url, json=payload, headers=headers, timeout=30)
    resp.raise_for_status()
    
    data = resp.json()
    return data["access_token"], data["refresh_token"], data.get("expires_in", 0)


@dataclass
class LoginResult:
    access_token: str
    refresh_token: str
    expires_in: int


def _wait_for_element(driver: webdriver.Chrome, by: By, value: str, timeout: int = 10):
    """Wait for an element to be present and visible."""
    return WebDriverWait(driver, timeout).until(
        EC.visibility_of_element_located((by, value))
    )


def _element_exists(driver: webdriver.Chrome, by: By, value: str) -> bool:
    """Check if an element exists on the page."""
    try:
        driver.find_element(by, value)
        return True
    except NoSuchElementException:
        return False


def _find_and_fill_input(driver: webdriver.Chrome, selectors: list[str], value: str, timeout: int = 15) -> None:
    """Find an input using multiple possible selectors and fill it."""
    input_el = None
    for selector in selectors:
        try:
            input_el = _wait_for_element(driver, By.CSS_SELECTOR, selector, timeout=timeout)
            if input_el:
                break
        except TimeoutException:
            continue
    
    if not input_el:
        raise ValueError(f"Could not find input with selectors: {selectors}")
    
    input_el.clear()
    input_el.send_keys(value)


def _find_and_click_button(driver: webdriver.Chrome, selectors: list[str]) -> None:
    """Find a button using multiple possible selectors and click it."""
    for selector in selectors:
        try:
            btn = driver.find_element(By.CSS_SELECTOR, selector)
            if btn.is_displayed() and btn.is_enabled():
                btn.click()
                return
        except NoSuchElementException:
            continue
    
    raise ValueError(f"Could not find clickable button with selectors: {selectors}")


def _check_for_error(driver: webdriver.Chrome) -> None:
    """Check if there's an error message on the page."""
    error_selectors = [
        ".error-message",
        ".tds-form-feedback--error",
        "[data-testid='error-message']",
        ".form-error",
        ".tds-form-input-error",
    ]
    
    for selector in error_selectors:
        try:
            error_el = driver.find_element(By.CSS_SELECTOR, selector)
            if error_el.is_displayed():
                error_text = error_el.text.strip()
                if error_text:
                    if "credentials" in error_text.lower() or "password" in error_text.lower():
                        raise ValueError("Invalid credentials")
                    if "could not sign you in" in error_text.lower():
                        raise ValueError("Invalid credentials")
                    raise ValueError(f"Login error: {error_text}")
        except NoSuchElementException:
            continue


def _is_mfa_page(driver: webdriver.Chrome) -> bool:
    """Check if we're on the MFA verification page."""
    mfa_indicators = [
        "input#form-input-passcode",
        "[data-testid='passcode-input']",
        "input[name='passcode']",
        "input[id*='passcode']",
    ]
    
    for selector in mfa_indicators:
        if _element_exists(driver, By.CSS_SELECTOR, selector):
            return True
    
    # Also check URL
    return "/mfa" in driver.current_url


def _is_password_page(driver: webdriver.Chrome) -> bool:
    """Check if we're on the password input page."""
    password_selectors = [
        "input#form-input-credential",
        "input[type='password']",
        "input[name='credential']",
    ]
    
    for selector in password_selectors:
        if _element_exists(driver, By.CSS_SELECTOR, selector):
            return True
    
    return False


def _wait_for_page_transition(driver: webdriver.Chrome, check_func, timeout: int = 15) -> bool:
    """Wait for a page transition to complete."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if check_func(driver):
            return True
        time.sleep(POLL_INTERVAL)
    return False


def start_login(
    email: str,
    password: str,
    *,
    locale: str = "zh-CN",
    passcode: Optional[str] = None,
    backup_code: Optional[str] = None,
) -> LoginResult:
    """
    Perform Tesla SSO login using browser automation.
    
    This approach lets the browser handle all JS challenges, Captcha, etc.
    We just automate form filling and wait for the callback URL.
    """
    # Generate PKCE parameters
    code_verifier, code_challenge, state = _generate_pkce()
    
    # Build authorize URL
    authorize_url = _build_authorize_url(code_challenge, state, locale)
    
    driver = _create_driver()
    
    try:
        # Navigate to authorize URL
        driver.get(authorize_url)
        
        # Wait for page to load
        time.sleep(3)
        
        # --- Step 1: Fill email (identity) ---
        email_selectors = [
            "input#form-input-identity",
            "input[name='identity']",
            "input[type='email']",
            "input#identity",
        ]
        _find_and_fill_input(driver, email_selectors, email)
        
        # Small delay before clicking
        time.sleep(0.5)
        
        # Click continue button
        button_selectors = [
            "button[type='submit']",
            "button#form-submit-continue",
            "button.tds-btn--primary",
            "button.tds-btn",
        ]
        _find_and_click_button(driver, button_selectors)
        
        # --- Step 2: Wait for password page and fill password ---
        if not _wait_for_page_transition(driver, _is_password_page, timeout=15):
            # Maybe it's a combined form, check if password field exists
            if not _is_password_page(driver):
                raise ValueError("Could not find password input after submitting email")
        
        time.sleep(1)
        
        password_selectors = [
            "input#form-input-credential",
            "input[type='password']",
            "input[name='credential']",
        ]
        _find_and_fill_input(driver, password_selectors, password)
        
        time.sleep(0.5)
        
        # Click submit button
        _find_and_click_button(driver, button_selectors)
        
        # --- Step 3: Wait for callback or MFA ---
        start_time = time.time()
        mfa_required = False
        
        while time.time() - start_time < MAX_WAIT_SECONDS:
            current_url = driver.current_url
            
            # Check if we hit the callback
            if _is_callback_url(current_url):
                break
            
            # Check for MFA
            if _is_mfa_page(driver):
                mfa_required = True
                break
            
            # Check for errors
            try:
                _check_for_error(driver)
            except ValueError:
                raise
            
            time.sleep(POLL_INTERVAL)
        else:
            if not _is_callback_url(driver.current_url) and not mfa_required:
                # Save screenshot for debugging
                try:
                    driver.save_screenshot("/tmp/tesla_timeout.png")
                except Exception:
                    pass
                raise TimeoutException(f"Timed out waiting for callback after {MAX_WAIT_SECONDS}s")
        
        # --- Step 4: Handle MFA if required ---
        if mfa_required:
            if not passcode and not backup_code:
                raise ValueError("MFA_REQUIRED")
            
            mfa_code = passcode or backup_code
            
            passcode_selectors = [
                "input#form-input-passcode",
                "[data-testid='passcode-input']",
                "input[name='passcode']",
                "input[id*='passcode']",
            ]
            _find_and_fill_input(driver, passcode_selectors, mfa_code, timeout=10)
            
            time.sleep(0.5)
            
            # Click submit
            _find_and_click_button(driver, button_selectors)
            
            # Wait for callback after MFA
            start_time = time.time()
            while time.time() - start_time < MAX_WAIT_SECONDS:
                if _is_callback_url(driver.current_url):
                    break
                _check_for_error(driver)
                time.sleep(POLL_INTERVAL)
            else:
                raise TimeoutException("Timed out waiting for callback after MFA")
        
        # --- Step 5: Extract code from callback URL ---
        callback_url = driver.current_url
        code, returned_state, issuer = _extract_code_from_url(callback_url)
        
        # Verify state
        if returned_state and returned_state != state:
            raise ValueError("CSRF state mismatch")
        
        # --- Step 6: Exchange code for tokens ---
        access_token, refresh_token, expires_in = _exchange_code_for_token(
            code, code_verifier, issuer
        )
        
        return LoginResult(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=expires_in,
        )
    
    finally:
        driver.quit()


# Compatibility stubs for main.py
def get_mfa_factors(session, transaction_id: str) -> list[dict]:
    """Get MFA factors - not used in browser approach, kept for compatibility."""
    return []


def verify_mfa(*args, **kwargs) -> None:
    """Verify MFA - not used in browser approach, kept for compatibility."""
    pass


def finish_and_exchange_token(*args, **kwargs) -> tuple[str, str]:
    """Not used in browser approach, kept for compatibility."""
    raise NotImplementedError("Use start_login() instead")
