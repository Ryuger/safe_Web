CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_active     BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE login_attempts (
    id         BIGSERIAL PRIMARY KEY,
    ip         INET NOT NULL,
    username   TEXT,
    success    BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_agent TEXT
);

CREATE TABLE ip_bans (
    ip           INET PRIMARY KEY,
    banned_until TIMESTAMPTZ NOT NULL,
    reason       TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id         BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor      TEXT,
    ip         INET,
    details    JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_login_attempts_ip_time ON login_attempts (ip, created_at DESC);
CREATE INDEX idx_login_attempts_user_time ON login_attempts (username, created_at DESC);
CREATE INDEX idx_ip_bans_until ON ip_bans (banned_until);
CREATE INDEX idx_audit_log_time ON audit_log (created_at DESC);
