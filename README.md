# tesla-broker (internal)

Internal HTTP service for Tesla SSO login/token exchange using **Playwright**.

## Why Playwright?

- Better anti-bot detection bypass compared to Selenium
- Uses real browser contexts with proper fingerprints
- Inspired by [tesla_auth](https://github.com/adriankumpf/tesla_auth) OAuth2 flow

## Run (Docker)

```bash
cd d:\odison\php\tesla-broker
docker compose up --build
```

Health check:

```bash
curl http://127.0.0.1:18080/health
```

## API

### POST /auth/start

Request:

```json
{
  "email": "user@example.com",
  "password": "...",
  "locale": "zh-CN"
}
```

With MFA:

```json
{
  "email": "user@example.com",
  "password": "...",
  "locale": "zh-CN",
  "passcode": "123456"
}
```

Response (success):

```json
{ "access_token": "...", "refresh_token": "...", "token_type": "Bearer", "expires_in": 28800 }
```

Response (MFA required):

```json
{ "status": "MFA_REQUIRED", "message": "MFA is required. Please include passcode in the request." }
```

## Debugging

```bash
docker cp tesla-broker-tesla-broker-1:/tmp/01_initial.png .
docker cp tesla-broker-tesla-broker-1:/tmp/01_initial.html .
```

## Security

- Run on internal network only
- Set `BROKER_SHARED_SECRET` env and send `X-Broker-Secret` header
- Do not log request bodies
