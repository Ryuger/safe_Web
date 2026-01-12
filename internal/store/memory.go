package store

import (
	"errors"
	"sync"
	"time"
)

type MemoryStore struct {
	mu       sync.Mutex
	users    map[string]User
	attempts []loginAttempt
	bans     map[string]ipBan
}

type loginAttempt struct {
	ip       string
	username string
	success  bool
	at       time.Time
}

type ipBan struct {
	until  time.Time
	reason string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users: map[string]User{},
		bans:  map[string]ipBan{},
	}
}

func (m *MemoryStore) IsBanned(ip string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ban, ok := m.bans[ip]
	if !ok {
		return false, nil
	}
	return ban.until.After(now), nil
}

func (m *MemoryStore) GetUser(username string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	user, ok := m.users[username]
	if !ok {
		return nil, errors.New("not found")
	}
	return &user, nil
}

func (m *MemoryStore) InsertAttempt(ip, username string, success bool, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attempts = append(m.attempts, loginAttempt{ip: ip, username: username, success: success, at: now})
	return nil
}

func (m *MemoryStore) CheckConsecutiveFailures(ip string, window time.Duration, limit int, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	cutoff := now.Add(-window)
	for i := len(m.attempts) - 1; i >= 0 && count < limit; i-- {
		attempt := m.attempts[i]
		if attempt.ip != ip || attempt.at.Before(cutoff) {
			continue
		}
		if attempt.success {
			return false, nil
		}
		count++
	}
	return count >= limit, nil
}

func (m *MemoryStore) UpsertBan(ip string, ttl time.Duration, reason string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bans[ip] = ipBan{until: now.Add(ttl), reason: reason}
	return nil
}

func (m *MemoryStore) InsertAudit(eventType, actor, ip, details string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return nil
}
