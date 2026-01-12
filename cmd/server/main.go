package main

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"safe_web/internal/auth"
	"safe_web/internal/store"
)

const (
	defaultListenAddr  = "127.0.0.1:8080"
	loginWindowMinutes = 10
	banTTLMinutes      = 60
	maxLoginBodyBytes  = 1 << 20
)

type App struct {
	Store store.Store
}

// dummyHash is a valid PBKDF2 hash used to normalize timing when a user is missing.
var dummyHash = "pbkdf2$200000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	listenAddr := getenv("LISTEN_ADDR", defaultListenAddr)

	st, err := store.NewStore()
	if err != nil {
		log.Fatalf("store init: %v", err)
	}

	app := &App{Store: st}

	mux := http.NewServeMux()
	mux.Handle("/login", app.ipGuard(http.HandlerFunc(app.loginHandler)))

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("listening on %s", listenAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

func (a *App) ipGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		ip := clientIPTrusted(r)

		banned, err := a.Store.IsBanned(ip, now)
		if err == nil && banned {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *App) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	now := time.Now()
	ip := clientIPTrusted(r)
	fail := func() {
		w.WriteHeader(http.StatusUnauthorized)
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
	var payload loginRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		fail()
		return
	}

	username := strings.TrimSpace(payload.Username)
	password := payload.Password
	if username == "" || password == "" {
		fail()
		return
	}

	banned, err := a.Store.IsBanned(ip, now)
	if err == nil && banned {
		_ = a.Store.InsertAudit("login_blocked", "", ip, `{"reason":"ip_banned"}`, now)
		fail()
		return
	}

	user, err := a.Store.GetUser(username)
	userActive := err == nil && user != nil && user.IsActive
	storedHash := dummyHash
	if userActive {
		storedHash = user.PasswordHash
	}

	passwordOK, verifyErr := auth.VerifyPassword(password, storedHash)
	if verifyErr != nil || err != nil || !userActive || !passwordOK {
		_ = a.Store.InsertAttempt(ip, username, false, now)

		shouldBan, checkErr := a.Store.CheckConsecutiveFailures(
			ip,
			time.Duration(loginWindowMinutes)*time.Minute,
			3,
			now,
		)
		if checkErr == nil && shouldBan {
			_ = a.Store.UpsertBan(ip, time.Duration(banTTLMinutes)*time.Minute, "3_failed_logins_in_10m", now)
			_ = a.Store.InsertAudit("ip_banned", username, ip, `{"reason":"3_failed_logins"}`, now)
		}

		fail()
		return
	}

	_ = a.Store.InsertAttempt(ip, username, true, now)
	_ = a.Store.InsertAudit("login_success", username, ip, `{}`, now)
	w.WriteHeader(http.StatusOK)
}

// Trust X-Real-IP only when the request originates from local NGINX.
func clientIPTrusted(r *http.Request) string {
	remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
	isFromLocalProxy := remoteHost == "127.0.0.1" || remoteHost == "::1"

	if isFromLocalProxy {
		if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
			return xrip
		}
	}

	if remoteHost != "" {
		return remoteHost
	}
	return "0.0.0.0"
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
