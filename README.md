# safe_Web

Single-binary HTTPS service for air-gapped or intranet deployments. No external proxy required.

## Quick start (Windows PowerShell)

> The service listens on `:8443` by default so it can run without Administrator rights. To bind `:443`, run PowerShell as Administrator and set `LISTEN_PUBLIC_ADDR=:443`.

```powershell
$env:LISTEN_PUBLIC_ADDR = ":8443"
$env:LISTEN_LOCAL_ADDR = "127.0.0.1:8080"
$env:WHITELIST_PATH = "config/ip_whitelist.txt"
$env:CERT_PATH = "config/cert.pem"
$env:KEY_PATH = "config/key.pem"
$env:BOOTSTRAP_USER = "admin"
$env:BOOTSTRAP_PASSWORD = "ChangeMeNow!"

go run ./cmd/server
```

## Generate a self-signed certificate (PowerShell)

```powershell
# Example self-signed cert for testing
openssl req -x509 -newkey rsa:4096 -keyout config/key.pem -out config/cert.pem -days 365 -nodes -subj "/CN=localhost"
```

## Postgres-backed mode

Build with the `postgres` tag and provide `DATABASE_URL`.

```powershell
$env:DATABASE_URL = "postgres://user:pass@127.0.0.1:5432/safe_web?sslmode=disable"

go build -tags postgres -o safe_web.exe ./cmd/server
./safe_web.exe
```

> Note: the Postgres build requires the `github.com/lib/pq` module to be available in your **local** module cache or offline registry.

## Create users (admin-only)

```powershell
go run ./cmd/admin/create_user --username admin --password 'ChangeMeNow!'
```

Paste the SQL into your database (see `examples/schema.sql`).

## Whitelist configuration

Edit `config/ip_whitelist.txt` with allowed IPs or CIDR ranges. Requests from non-whitelisted IPs receive a minimal 404 response.

## Files

- `cmd/server`: HTTPS server with whitelist/blacklist, login, and sessions.
- `cmd/admin/create_user`: admin-only helper to create user SQL.
- `config/ip_whitelist.txt`: whitelist file (IP/CIDR).
- `examples/schema.sql`: Postgres schema + indexes.

## Minimal test plan

1. **Whitelist enforcement**: remove your IP from `config/ip_whitelist.txt` and confirm `GET /` returns empty 404.
2. **Login ban**: perform 3 failed logins within 10 minutes from a whitelisted IP and verify subsequent attempts are blocked for 60 minutes.
3. **Password expiry**: set `password_changed_at` > 90 days ago and verify login redirects to `/change-password`.
4. **Password change**: confirm complexity rules, mismatch errors, and new password rejection when reusing the old password.
