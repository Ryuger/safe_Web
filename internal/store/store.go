package store

import "time"

type User struct {
	Username     string
	PasswordHash string
	IsActive     bool
}

type Store interface {
	IsBanned(ip string, now time.Time) (bool, error)
	GetUser(username string) (*User, error)
	InsertAttempt(ip, username string, success bool, now time.Time) error
	CheckConsecutiveFailures(ip string, window time.Duration, limit int, now time.Time) (bool, error)
	UpsertBan(ip string, ttl time.Duration, reason string, now time.Time) error
	InsertAudit(eventType, actor, ip, details string, now time.Time) error
}
