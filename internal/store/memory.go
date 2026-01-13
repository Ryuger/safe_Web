package store

import (
	"errors"
	"log"
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

func (m *MemoryStore) AddUser(username, passwordHash string, active bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[username] = User{Username: username, PasswordHash: passwordHash, IsActive: active}
}

func (m *MemoryStore) IsBanned(ip string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneBans(now)
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
	m.pruneAttempts(now.Add(-window))
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
	log.Printf("audit event=%s actor=%s ip=%s details=%s", eventType, actor, ip, details)
	return nil
}

func (m *MemoryStore) pruneBans(now time.Time) {
	for ip, ban := range m.bans {
		if !ban.until.After(now) {
			delete(m.bans, ip)
		}
	}
}

func (m *MemoryStore) pruneAttempts(cutoff time.Time) {
	if len(m.attempts) == 0 {
		return
	}

	idx := 0
	for _, attempt := range m.attempts {
		if attempt.at.After(cutoff) {
			m.attempts[idx] = attempt
			idx++
		}
	}
	m.attempts = m.attempts[:idx]
}
