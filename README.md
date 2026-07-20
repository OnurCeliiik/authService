# authService
An authentication service written in Go

## Skills and Technologies Used:
* Go (gin)
* PostgreSQL (Database)
* User security
* RESTful API Design
* OAuth (Third-Party Login)



**Project Overview**: Create a secure login system. Users can sign up, log in, reset passwords, use Google login. 

### API Responsibilities

#### User Authentication
    * Sign up and log in with email and password.
    * Reset password via email.
    * Support Google login with OAuth.
    * Secure endpoints with tokens.


#### Local Setup

```bash
cp .env.example .env
docker compose up -d          
go run ./cmd/api              

# Or run it via Makefile command:
make up 
```

Environment variables (see `.env.example`):

| Variable | Description |
|----------|-------------|
| `PORT` | HTTP listen port (default `8080`) |
| `DATABASE_URL` | Postgres DSN |
| `JWT_SECRET` | HMAC secret for access tokens |
| `JWT_TTL` | Access token lifetime (e.g. `15m`) |
| `REFRESH_TOKEN_TTL` | Refresh token lifetime (e.g. `168h`) |
| `APP_BASE_URL` | Base URL used in password-reset email links |
| `SMTP_HOST` | SMTP host (empty = log emails instead of sending) |
| `SMTP_PORT` | SMTP port (default `1025`) |
| `SMTP_FROM` | From address for outbound mail |
| `EXPOSE_RESET_TOKEN` | If `true`, include `reset_token` in forgot-password JSON (dev/tests only) |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID (empty = OAuth disabled) |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `GOOGLE_REDIRECT_URI` | Must match Google Console, e.g. `http://localhost:8080/api/v1/oauth/google/callback` |

Local mail: `docker compose up -d mailpit` then open [http://localhost:8025](http://localhost:8025) to inspect password-reset emails. Manual API checks: `api.http`.

Google login: open [http://localhost:8080/api/v1/oauth/google](http://localhost:8080/api/v1/oauth/google) in a browser. After consent you land on the callback and receive the same access/refresh JSON as password login.

#### API (v1)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | No | Liveness + DB ping |
| POST | `/api/v1/signup` | No | Register with email/password |
| POST | `/api/v1/login` | No | Issue access + refresh tokens |
| POST | `/api/v1/refresh` | No | Rotate refresh token and issue a new access token |
| GET | `/api/v1/oauth/google` | No | Redirect to Google sign-in |
| GET | `/api/v1/oauth/google/callback` | No | Google redirect target; returns access + refresh tokens |
| POST | `/api/v1/forgot-password` | No | Start password reset (email + optional `reset_token` if exposed) |
| POST | `/api/v1/reset-password` | No | Set new password with reset token |
| GET | `/api/v1/me` | Bearer JWT | Current user profile |
| PATCH | `/api/v1/me` | Bearer JWT | Update first/last name |
| POST | `/api/v1/change-password` | Bearer JWT | Change password (invalidates access + refresh tokens) |
| POST | `/api/v1/logout` | Bearer JWT | Invalidate access tokens and revoke all refresh tokens |

