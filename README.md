# safe_Web

Minimal offline-friendly login service with hardened NGINX example and Postgres schema.

## Quick start (in-memory)

```bash
export BOOTSTRAP_USER=admin
export BOOTSTRAP_PASSWORD='ChangeMeNow!'
export LISTEN_ADDR=127.0.0.1:8080

go run ./cmd/server
```

- The in-memory store is for local testing only.
- The backend **must** listen on `127.0.0.1` so it is reachable only from NGINX.

## Postgres-backed mode

Build with the `postgres` tag and provide `DATABASE_URL`.

```bash
export DATABASE_URL='postgres://user:pass@127.0.0.1:5432/safe_web?sslmode=disable'

go build -tags postgres -o safe_web ./cmd/server
./safe_web
```

> Note: the Postgres build requires the `github.com/lib/pq` module to be available in your **local** module cache or offline registry.

## Create users (admin-only)

Generate a password hash and insert statement:

```bash
go run ./cmd/admin/create_user --username admin --password 'ChangeMeNow!'
```

Paste the SQL into your database (see `examples/schema.sql`).

## NGINX configuration

Use `examples/nginx.conf` as a base. Copy the whitelist/blacklist templates to NGINX:

```bash
sudo cp examples/ip_whitelist.conf /etc/nginx/ip_whitelist.conf
sudo cp examples/ip_blacklist.conf /etc/nginx/ip_blacklist.conf
```

Update the allowed IPs in `/etc/nginx/ip_whitelist.conf` and reload NGINX.

The backend **must** remain bound to `127.0.0.1:8080` so the only public entrypoint is NGINX on 443.

## Files

- `examples/nginx.conf`: hardened NGINX config (whitelist/blacklist, rate limit, security headers).
- `examples/schema.sql`: Postgres schema + indexes.
- `examples/ip_whitelist.conf`: whitelist template (copy to `/etc/nginx`).
- `examples/ip_blacklist.conf`: blacklist template (copy to `/etc/nginx`).
