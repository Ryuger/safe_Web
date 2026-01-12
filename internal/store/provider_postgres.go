//go:build postgres

package store

import (
	"database/sql"
	"errors"
	"os"
	"time"

	_ "github.com/lib/pq"
)

const defaultMaxConns = 10

type PostgresStore struct {
	db *sql.DB
}

func NewStore() (Store, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, errors.New("DATABASE_URL is required")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(defaultMaxConns)
	db.SetMaxIdleConns(defaultMaxConns)
	db.SetConnMaxLifetime(30 * time.Minute)

	return &PostgresStore{db: db}, nil
}

func (p *PostgresStore) IsBanned(ip string, now time.Time) (bool, error) {
	var bannedUntil time.Time
	err := p.db.QueryRow(
		`SELECT banned_until FROM ip_bans WHERE ip = $1 AND banned_until > $2`,
		ip, now,
	).Scan(&bannedUntil)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (p *PostgresStore) GetUser(username string) (*User, error) {
	var user User
	err := p.db.QueryRow(
		`SELECT username, password_hash, is_active FROM users WHERE username = $1`,
		username,
	).Scan(&user.Username, &user.PasswordHash, &user.IsActive)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (p *PostgresStore) InsertAttempt(ip, username string, success bool, now time.Time) error {
	_, err := p.db.Exec(
		`INSERT INTO login_attempts (ip, username, success, created_at) VALUES ($1,$2,$3,$4)`,
		ip, username, success, now,
	)
	return err
}

func (p *PostgresStore) CheckConsecutiveFailures(ip string, window time.Duration, limit int, now time.Time) (bool, error) {
	rows, err := p.db.Query(`
		SELECT success
		FROM login_attempts
		WHERE ip = $1 AND created_at >= $2
		ORDER BY created_at DESC
		LIMIT $3
	`, ip, now.Add(-window), limit)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var success bool
		if err := rows.Scan(&success); err != nil {
			return false, err
		}
		if success {
			return false, nil
		}
		count++
	}
	return count >= limit, nil
}

func (p *PostgresStore) UpsertBan(ip string, ttl time.Duration, reason string, now time.Time) error {
	_, err := p.db.Exec(`
		INSERT INTO ip_bans (ip, banned_until, reason, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (ip) DO UPDATE
		SET banned_until = EXCLUDED.banned_until, reason = EXCLUDED.reason
	`, ip, now.Add(ttl), reason, now)
	return err
}

func (p *PostgresStore) InsertAudit(eventType, actor, ip, details string, now time.Time) error {
	_, err := p.db.Exec(
		`INSERT INTO audit_log (event_type, actor, ip, details, created_at) VALUES ($1,$2,$3,$4::jsonb,$5)`,
		eventType, actor, ip, details, now,
	)
	return err
}
