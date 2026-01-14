# tesla-broker (internal)

Internal HTTP service that wraps Tesla SSO login/token exchange.

## Run (Docker)

From this folder:

- `docker compose up --build`
- Health check: `curl http://127.0.0.1:8080/health`

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
{ "access_token": "...", "refresh_token": "...", "token_type": "Bearer" }
```

- MFA required:

```json
{ "status": "MFA_REQUIRED", "flow_id": "...", "transaction_id": "...", "factors": [ {"id":"...","name":"Device #1"} ] }
```

### POST /auth/mfa/verify

Request JSON:

```json
{ "flow_id": "...", "factor_id": "...", "passcode": "123456" }
```

Response:

```json
{ "access_token": "...", "refresh_token": "...", "token_type": "Bearer" }
```

## Security

- Run on internal network only.
- Optionally set `BROKER_SHARED_SECRET` and send header `X-Broker-Secret` from Laravel.
- Do not log request bodies.
