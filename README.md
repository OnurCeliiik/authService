# authService
An authentication service written in Go

## skills and Technologies Used:
* Go (gin)
* PostgreSQL (Database)
* User security
* RESTful API Design
* OAuth (Third-Party Login)



**Project Overview**: Create a secure login system. Users can sign up, log in, reset passwords, use Google login. 

### API Responsibilites

#### User Authentication
    * Sign up and log in with email and password.
    * Reset password via email.
    * Support Google login with OAuth.
    * Secure endpoints with tokens.

#### Task Operations
    * Create a new task: Allow users to add a a task with a title (ex: "Reset Password"), and description (ex: reset instructions).
    * Read tasks:
        * Return all authentication-related tasks for the authenticated user.
        * Filter by status (ex: completed or pending).
        * Retrieve a single task by its ID.
    * Update a task: Modify task details (ex: update reset status) or mark as completed/pending using its ID.
    * Delete a task: Remove an authentication task based on it's ID.


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
| `JWT_TTL` | Token lifetime (e.g. `24h`) |

#### API (v1)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness + DB ping |
| POST | `/api/v1/signup` | Register with email/password |
| POST | `/api/v1/login` | Issue Bearer access token |
