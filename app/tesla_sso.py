"""
Tesla SSO Token Broker - using Playwright

Inspired by https://github.com/adriankumpf/tesla_auth
Uses Playwright for better anti-bot detection bypass.

Core flow:
1. Generate PKCE parameters (same as tesla_auth)
2. Open Tesla login page in Playwright browser
3. Automate form filling (email, password, MFA if needed)
4. Wait for redirect to void/callback with code
5. Exchange code for tokens using OAuth2

Key difference from Selenium: Playwright has better anti-detection
and can use real browser contexts with persistent state.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse

import requests
from playwright.sync_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    sync_playwright,
    TimeoutError as PlaywrightTimeout,
)

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Configuration (same as tesla_auth)
CLIENT_ID = "ownerapi"
AUTH_URL = "https://auth.tesla.com/oauth2/v3/authorize"
AUTH_URL_CN = "https://auth.tesla.cn/oauth2/v3/authorize"
TOKEN_URL = "https://auth.tesla.com/oauth2/v3/token"
TOKEN_URL_CN = "https://auth.tesla.cn/oauth2/v3/token"
REDIRECT_URI = "https://auth.tesla.com/void/callback"
SCOPES = "openid email offline_access"

# Timeouts
PAGE_TIMEOUT = int(os.getenv("PAGE_TIMEOUT", "30000"))  # 30s
NAVIGATION_TIMEOUT = int(os.getenv("NAVIGATION_TIMEOUT", "60000"))  # 60s


def _generate_pkce() -> tuple[str, str, str]:
    """Generate PKCE code_verifier, code_challenge, and state (same as tesla_auth)."""
    logger.info("Generating PKCE parameters...")
    
    # Random 32 bytes for verifier
    verifier_bytes = os.urandom(32)
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b"=").decode("utf-8")
    
    # SHA256 hash of verifier for challenge
    challenge_bytes = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = base64.urlsafe_b64encode(challenge_bytes).rstrip(b"=").decode("utf-8")
    
    # Random state for CSRF protection
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode("utf-8")
    
    logger.debug(f"PKCE state: {state[:10]}...")
    return code_verifier, code_challenge, state


def _build_authorize_url(code_challenge: str, state: str, locale: str = "zh-CN", use_cn: bool = True) -> str:
    """Build the Tesla OAuth2 authorize URL."""
    base_url = AUTH_URL_CN if use_cn else AUTH_URL
    
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
    
    url = f"{base_url}?{urlencode(params)}"
    logger.info(f"Built authorize URL (CN={use_cn}, locale={locale})")
    return url


def _is_callback_url(url: str) -> bool:
    """Check if URL is the OAuth callback."""
    return url.startswith(REDIRECT_URI)


def _extract_callback_params(url: str) -> tuple[str, str, Optional[str]]:
    """Extract code, state, and issuer from callback URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if "error" in params:
        error = params["error"][0]
        if error == "login_cancelled":
            raise ValueError("Login was cancelled")
        raise ValueError(f"OAuth error: {error}")
    
    if "code" not in params:
        raise ValueError("No authorization code in callback URL")
    
    code = params["code"][0]
    state = params.get("state", [""])[0]
    issuer = params.get("issuer", [None])[0]
    
    return code, state, issuer


def _exchange_code_for_tokens(code: str, code_verifier: str, issuer: Optional[str] = None) -> tuple[str, str, int]:
    """Exchange authorization code for access/refresh tokens."""
    # Use CN token URL if issuer is from China (same logic as tesla_auth)
    if issuer and "tesla.cn" in issuer:
        token_url = TOKEN_URL_CN
        logger.info("Using Tesla CN token endpoint")
    else:
        token_url = TOKEN_URL
        logger.info("Using Tesla global token endpoint")
    
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
    
    logger.info("Exchanging code for tokens...")
    resp = requests.post(token_url, json=payload, headers=headers, timeout=30)
    resp.raise_for_status()
    
    data = resp.json()
    logger.info("Token exchange successful!")
    return data["access_token"], data["refresh_token"], data.get("expires_in", 0)


@dataclass
class LoginResult:
    access_token: str
    refresh_token: str
    expires_in: int


def _save_debug_artifacts(page: Page, name: str) -> None:
    """Save screenshot and HTML for debugging."""
    try:
        page.screenshot(path=f"/tmp/{name}.png")
        logger.info(f"Screenshot saved: /tmp/{name}.png")
        
        with open(f"/tmp/{name}.html", "w", encoding="utf-8") as f:
            f.write(page.content())
        logger.info(f"HTML saved: /tmp/{name}.html")
    except Exception as e:
        logger.warning(f"Failed to save debug artifacts: {e}")


def start_login(
    email: str,
    password: str,
    *,
    locale: str = "zh-CN",
    passcode: Optional[str] = None,
    backup_code: Optional[str] = None,
) -> LoginResult:
    """
    Perform Tesla SSO login using Playwright browser automation.
    
    This approach uses Playwright which has better anti-bot detection bypass
    compared to Selenium. We use a real browser context with proper fingerprints.
    """
    logger.info(f"=== Starting Tesla SSO login for {email[:3]}***@*** ===")
    logger.info(f"Locale: {locale}")
    
    # Generate PKCE parameters
    code_verifier, code_challenge, state = _generate_pkce()
    
    # Build authorize URL (use CN for Chinese users)
    use_cn = locale.lower().startswith("zh")
    authorize_url = _build_authorize_url(code_challenge, state, locale, use_cn)
    
    with sync_playwright() as p:
        # Launch browser with anti-detection settings
        logger.info("Launching browser...")
        browser = p.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
            ]
        )
        
        # Create context with realistic settings
        context = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            locale=locale,
            timezone_id="Asia/Shanghai" if use_cn else "America/Los_Angeles",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        )
        
        # Add anti-detection scripts
        context.add_init_script("""
            // Remove webdriver property
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });
            
            // Add plugins
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5]
            });
            
            // Add languages
            Object.defineProperty(navigator, 'languages', {
                get: () => ['zh-CN', 'zh', 'en-US', 'en']
            });
            
            // Add chrome object
            window.chrome = {
                runtime: {}
            };
        """)
        
        page = context.new_page()
        page.set_default_timeout(PAGE_TIMEOUT)
        
        try:
            # Navigate to authorize URL
            logger.info("Navigating to Tesla login page...")
            page.goto(authorize_url, wait_until="networkidle", timeout=NAVIGATION_TIMEOUT)
            
            logger.info(f"Page loaded. URL: {page.url}")
            logger.info(f"Page title: {page.title()}")
            
            _save_debug_artifacts(page, "01_initial")
            
            # Check for access denied
            if "Access Denied" in page.content():
                logger.error("Access Denied by Tesla CDN!")
                _save_debug_artifacts(page, "access_denied")
                raise ValueError("Access Denied by Tesla - IP may be blocked")
            
            # --- Step 1: Fill email ---
            logger.info("Step 1: Looking for email input...")
            
            email_selectors = [
                "input#form-input-identity",
                "input[name='identity']",
                "input[type='email']",
                "#identity",
            ]
            
            email_input = None
            for selector in email_selectors:
                try:
                    email_input = page.wait_for_selector(selector, timeout=5000)
                    if email_input:
                        logger.info(f"Found email input: {selector}")
                        break
                except PlaywrightTimeout:
                    continue
            
            if not email_input:
                _save_debug_artifacts(page, "no_email_input")
                raise ValueError("Could not find email input field")
            
            email_input.fill(email)
            logger.info("Email filled")
            
            # Click continue
            page.wait_for_timeout(500)
            submit_btn = page.locator("button[type='submit']").first
            submit_btn.click()
            logger.info("Clicked continue button")
            
            _save_debug_artifacts(page, "02_after_email")
            
            # --- Step 2: Wait for password page and fill ---
            logger.info("Step 2: Waiting for password input...")
            page.wait_for_timeout(2000)
            
            password_selectors = [
                "input#form-input-credential",
                "input[type='password']",
                "input[name='credential']",
            ]
            
            password_input = None
            for selector in password_selectors:
                try:
                    password_input = page.wait_for_selector(selector, timeout=5000)
                    if password_input and password_input.is_visible():
                        logger.info(f"Found password input: {selector}")
                        break
                except PlaywrightTimeout:
                    continue
            
            if not password_input:
                _save_debug_artifacts(page, "no_password_input")
                raise ValueError("Could not find password input field")
            
            password_input.fill(password)
            logger.info("Password filled")
            
            # Click login
            page.wait_for_timeout(500)
            submit_btn = page.locator("button[type='submit']").first
            submit_btn.click()
            logger.info("Clicked login button")
            
            _save_debug_artifacts(page, "03_after_password")
            
            # --- Step 3: Wait for callback or MFA ---
            logger.info("Step 3: Waiting for callback or MFA...")
            
            # Wait for navigation with callback URL or MFA page
            deadline = NAVIGATION_TIMEOUT
            mfa_required = False
            
            try:
                # Wait for either callback URL or MFA page
                page.wait_for_function(
                    f"""() => {{
                        const url = window.location.href;
                        if (url.startsWith("{REDIRECT_URI}")) return true;
                        if (url.includes("/mfa")) return true;
                        if (document.querySelector('input[name="passcode"]')) return true;
                        return false;
                    }}""",
                    timeout=deadline,
                )
            except PlaywrightTimeout:
                _save_debug_artifacts(page, "timeout_waiting")
                # Check for error messages
                error_el = page.locator(".tds-form-feedback--error, .error-message").first
                if error_el.is_visible():
                    error_text = error_el.text_content()
                    raise ValueError(f"Login error: {error_text}")
                raise ValueError("Timeout waiting for login to complete")
            
            current_url = page.url
            logger.info(f"Navigation complete. URL: {current_url}")
            
            # Check if MFA required
            if "/mfa" in current_url or page.locator('input[name="passcode"]').count() > 0:
                logger.info("MFA page detected")
                mfa_required = True
                _save_debug_artifacts(page, "04_mfa_page")
            
            # --- Step 4: Handle MFA if required ---
            if mfa_required:
                if not passcode and not backup_code:
                    logger.warning("MFA required but no passcode provided")
                    raise ValueError("MFA_REQUIRED")
                
                mfa_code = passcode or backup_code
                logger.info("Entering MFA code...")
                
                passcode_input = page.locator('input[name="passcode"], input#form-input-passcode').first
                passcode_input.fill(mfa_code)
                
                page.wait_for_timeout(500)
                submit_btn = page.locator("button[type='submit']").first
                submit_btn.click()
                logger.info("MFA submitted")
                
                # Wait for callback
                try:
                    page.wait_for_url(f"{REDIRECT_URI}*", timeout=NAVIGATION_TIMEOUT)
                except PlaywrightTimeout:
                    _save_debug_artifacts(page, "mfa_timeout")
                    raise ValueError("Timeout after MFA submission")
            
            # --- Step 5: Extract code from callback ---
            callback_url = page.url
            logger.info(f"Callback URL: {callback_url}")
            
            if not _is_callback_url(callback_url):
                _save_debug_artifacts(page, "not_callback")
                raise ValueError(f"Not a callback URL: {callback_url}")
            
            code, returned_state, issuer = _extract_callback_params(callback_url)
            logger.info(f"Got authorization code (issuer: {issuer})")
            
            # Verify state for CSRF protection
            if returned_state and returned_state != state:
                raise ValueError("CSRF state mismatch!")
            
            # --- Step 6: Exchange code for tokens ---
            access_token, refresh_token, expires_in = _exchange_code_for_tokens(
                code, code_verifier, issuer
            )
            
            logger.info("=== Login successful! ===")
            logger.info(f"Token expires in: {expires_in}s")
            
            return LoginResult(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=expires_in,
            )
            
        finally:
            logger.info("Closing browser...")
            context.close()
            browser.close()
