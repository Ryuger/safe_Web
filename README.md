# safe_Web

Single-binary HTTPS service for air-gapped or intranet deployments. No external proxy required.

## Architecture

- **Public server**: HTTPS, user login, optional mTLS, enrollment endpoint.
- **Admin server**: local-only UI (`127.0.0.1`), manages clients/tokens/certs/settings/audit.

## Quick start (Windows PowerShell)

> The public server listens on `:8443` by default. To bind `:443`, run PowerShell as Administrator and set `LISTEN_PUBLIC_ADDR=:443`.

```powershell
$env:LISTEN_PUBLIC_ADDR = ":8443"
$env:LISTEN_ADMIN_ADDR = "127.0.0.1:9443"
$env:LISTEN_LOCAL_ADDR = "127.0.0.1:8080"
$env:WHITELIST_PATH = "config/ip_whitelist.txt"
$env:PUBLIC_CERT_PATH = "config/cert.pem"
$env:PUBLIC_KEY_PATH = "config/key.pem"
$env:BOOTSTRAP_USER = "admin"
$env:BOOTSTRAP_PASSWORD = "ChangeMeNow!"
$env:BOOTSTRAP_ADMIN_USER = "localadmin"
$env:BOOTSTRAP_ADMIN_PASSWORD = "ChangeMeNow!"

# For Postgres builds
$env:DB_DSN = "postgres://user:pass@127.0.0.1:5432/safe_web?sslmode=disable"

# Optional mTLS / enrollment
$env:MTLS_ENABLED = "false"
$env:ENROLL_ENABLED = "true"
$env:CLIENT_CA_PATH = "config/client_ca.pem"
$env:CA_CERT_PATH = "config/ca_cert.pem"
$env:CA_KEY_PATH = "config/ca_key.pem"

# Admin TLS (optional)
$env:ADMIN_TLS_ENABLED = "false"
$env:ADMIN_CERT_PATH = "config/admin_cert.pem"
$env:ADMIN_KEY_PATH = "config/admin_key.pem"

# Build for Postgres
# go build -tags postgres -o safe_web.exe ./cmd/server
# Run
# ./safe_web.exe

go run ./cmd/server
```

## Generate a self-signed certificate (PowerShell)

```powershell
openssl req -x509 -newkey rsa:4096 -keyout config/key.pem -out config/cert.pem -days 365 -nodes -subj "/CN=localhost"
```

## Admin UI (local only)

- Admin UI listens on `LISTEN_ADMIN_ADDR` and only accepts loopback clients.
- Visit `https://127.0.0.1:9443/admin/login` (or `http://` if `ADMIN_TLS_ENABLED=false`).

## Enrollment flow (mTLS clients)

1. Admin creates a client.
2. Admin issues an enrollment token from `/admin/clients/{id}` (shown once).
3. Client generates a CSR and POSTs to `/enroll` with `client_id`, `csr_pem`, and `token`.
4. Server verifies token + CSR and returns a signed client certificate.

## Files

- `cmd/server`: public + admin HTTPS servers.
- `cmd/admin/create_user`: helper to create user SQL.
- `config/ip_whitelist.txt`: whitelist file (IP/CIDR).
- `examples/schema.sql`: Postgres schema + indexes.

## Minimal test plan

1. **Whitelist enforcement**: remove your IP from `config/ip_whitelist.txt` and confirm `GET /` returns empty 404.
2. **Login ban**: perform 3 failed logins within 10 minutes from a whitelisted IP and verify subsequent attempts are blocked for 60 minutes.
3. **Password expiry**: set `password_changed_at` > 90 days ago and verify login redirects to `/change-password`.
4. **Admin loopback**: try hitting admin UI from a non-loopback interface and confirm a minimal 404.
5. **Enrollment tokens**: generate a token, use it once, verify second use fails; verify expired tokens fail.
