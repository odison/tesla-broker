# tesla-broker (internal)

Internal HTTP service that wraps Tesla SSO login/token exchange using **full browser automation**.

Inspired by [tesla_auth](https://github.com/adriankumpf/tesla_auth) - the browser handles all JS challenges, Captcha, etc. We just automate form filling and wait for the OAuth callback.

## Run (Docker)

From this folder:

- `docker compose up --build`
- Health check: `curl http://127.0.0.1:18080/health`

## API

### POST /auth/start

Request JSON:

```json
{
  "email": "user@example.com",
  "password": "...",
  "locale": "zh-CN"
}
```

Response:

- Success:

```json
{ "access_token": "...", "refresh_token": "...", "token_type": "Bearer", "expires_in": 28800 }
```

- MFA required (no passcode provided):

```json
{ "status": "MFA_REQUIRED", "flow_id": "browser-session", "transaction_id": "browser-session", "factors": [] }
```

### Handling MFA

In browser mode, MFA is handled in a single request. If you get `MFA_REQUIRED`, retry `/auth/start` with the passcode included:

```json
{
  "email": "user@example.com",
  "password": "...",
  "locale": "zh-CN",
  "passcode": "123456"
}
```

Or with backup code:

```json
{
  "email": "user@example.com",
  "password": "...",
  "locale": "zh-CN",
  "backup_code": "ABCD-1234-EFGH"
}
```

## Security

- Run on internal network only.
- Optionally set `BROKER_SHARED_SECRET` and send header `X-Broker-Secret` from Laravel.
- Do not log request bodies.

## How it works

1. Opens headless Chrome and navigates to Tesla OAuth authorize URL
2. Automatically fills email, clicks continue
3. Fills password, submits
4. Waits for redirect to `https://auth.tesla.com/void/callback?code=xxx`
5. Extracts `code` from URL and exchanges it for tokens via standard OAuth2

This approach avoids parsing HTML/CSRF tokens and lets the real browser handle all JavaScript challenges.
