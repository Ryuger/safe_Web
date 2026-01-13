package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"safe_web/internal/auth"
	"safe_web/internal/ratelimit"
	"safe_web/internal/session"
	"safe_web/internal/store"
	"safe_web/internal/web"
	"safe_web/internal/whitelist"
)

const (
	defaultPublicAddr = ":8443"
	defaultLocalAddr  = ""
	defaultCertPath   = "config/cert.pem"
	defaultKeyPath    = "config/key.pem"
	defaultWLPath     = "config/ip_whitelist.txt"

	loginWindowMinutes = 10
	banTTLMinutes      = 60
	maxLoginBodyBytes  = 1 << 20
	passwordMaxAge     = 90 * 24 * time.Hour
	sessionTTL         = 8 * time.Hour
)

type App struct {
	Store      store.Store
	Whitelist  *whitelist.List
	Limiter    *ratelimit.Limiter
	Sessions   *session.Store
	DummyHash  string
	CookieName string
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type templateData struct {
	CSRFToken         string
	Error             string
	Username          string
	PasswordChangedAt string
}

func main() {
	publicAddr := getenv("LISTEN_PUBLIC_ADDR", defaultPublicAddr)
	localAddr := getenv("LISTEN_LOCAL_ADDR", defaultLocalAddr)
	certPath := getenv("CERT_PATH", defaultCertPath)
	keyPath := getenv("KEY_PATH", defaultKeyPath)
	whitelistPath := getenv("WHITELIST_PATH", defaultWLPath)

	wl, err := whitelist.Load(whitelistPath)
	if err != nil {
		log.Fatalf("load whitelist: %v", err)
	}

	st, err := store.NewStore()
	if err != nil {
		log.Fatalf("store init: %v", err)
	}

	dummyHash, err := auth.HashPassword("dummy-password")
	if err != nil {
		log.Fatalf("dummy hash: %v", err)
	}

	app := &App{
		Store:      st,
		Whitelist:  wl,
		Limiter:    ratelimit.New(5, time.Minute),
		Sessions:   session.NewStore(sessionTTL),
		DummyHash:  dummyHash,
		CookieName: "session_id",
	}

	bootstrapMemoryUser(app)

	publicMux := http.NewServeMux()
	publicMux.Handle("/", app.ipGuard(app.securityHeaders(http.HandlerFunc(app.indexHandler))))
	publicMux.Handle("/login", app.ipGuard(app.securityHeaders(http.HandlerFunc(app.loginHandler))))
	publicMux.Handle("/app", app.ipGuard(app.securityHeaders(http.HandlerFunc(app.appHandler))))
	publicMux.Handle("/change-password", app.ipGuard(app.securityHeaders(http.HandlerFunc(app.changePasswordHandler))))

	publicServer := &http.Server{
		Addr:              publicAddr,
		Handler:           publicMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
		},
	}

	if localAddr != "" {
		localMux := http.NewServeMux()
		localMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		localServer := &http.Server{
			Addr:              localAddr,
			Handler:           localMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       60 * time.Second,
		}

		go func() {
			log.Printf("local http listening on %s", localAddr)
			if err := localServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("local server error: %v", err)
			}
		}()
	}

	log.Printf("public https listening on %s", publicAddr)
	if err := publicServer.ListenAndServeTLS(certPath, keyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("public server error: %v", err)
	}
}

func (a *App) ipGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if ip == nil {
			minimalResponse(w)
			return
		}
		if !a.Whitelist.Allowed(ip) {
			minimalResponse(w)
			return
		}

		banned, err := a.Store.IsBanned(ip.String(), time.Now())
		if err == nil && banned {
			minimalResponse(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Del("Server")
		next.ServeHTTP(w, r)
	})
}

func (a *App) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	csrfToken, err := a.issueCSRFCookie(w)
	if err != nil {
		minimalResponse(w)
		return
	}

	web.Render(w, "index.html", templateData{CSRFToken: csrfToken})
}

func (a *App) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ip := clientIP(r)
	if ip == nil {
		minimalResponse(w)
		return
	}
	ipStr := ip.String()

	if !a.Limiter.Allow(ipStr, time.Now()) {
		minimalResponse(w)
		return
	}

	if !a.verifyCSRF(r) {
		minimalResponse(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodyBytes)
	payload, err := parseLoginRequest(r)
	if err != nil {
		a.renderLoginError(w)
		return
	}

	username := strings.TrimSpace(payload.Username)
	password := payload.Password
	if username == "" || password == "" {
		a.renderLoginError(w)
		return
	}

	banned, err := a.Store.IsBanned(ipStr, time.Now())
	if err == nil && banned {
		_ = a.Store.InsertAudit("login_blocked", "", ipStr, `{"reason":"ip_banned"}`, time.Now())
		minimalResponse(w)
		return
	}

	user, err := a.Store.GetUser(username)
	userActive := err == nil && user != nil && user.IsActive
	storedHash := a.DummyHash
	if userActive {
		storedHash = user.PasswordHash
	}

	passwordOK, verifyErr := auth.VerifyPassword(password, storedHash)
	if verifyErr != nil || err != nil || !userActive || !passwordOK {
		_ = a.Store.InsertAttempt(ipStr, username, false, time.Now())

		shouldBan, checkErr := a.Store.CheckConsecutiveFailures(
			ipStr,
			time.Duration(loginWindowMinutes)*time.Minute,
			3,
			time.Now(),
		)
		if checkErr == nil && shouldBan {
			_ = a.Store.UpsertBan(ipStr, time.Duration(banTTLMinutes)*time.Minute, "3_failed_logins_in_10m", time.Now())
			_ = a.Store.InsertAudit("ip_banned", username, ipStr, `{"reason":"3_failed_logins"}`, time.Now())
		}

		a.renderLoginError(w)
		return
	}

	_ = a.Store.InsertAttempt(ipStr, username, true, time.Now())
	_ = a.Store.InsertAudit("login_success", username, ipStr, `{}`, time.Now())

	mustChange := time.Since(user.PasswordChangedAt) > passwordMaxAge
	sess, err := a.Sessions.Create(username, mustChange, time.Now())
	if err != nil {
		minimalResponse(w)
		return
	}

	setSessionCookie(w, a.CookieName, sess.ID)
	setCSRFCookie(w, sess.CSRFToken)

	if mustChange {
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/app", http.StatusSeeOther)
}

func (a *App) appHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	sess, ok := a.requireSession(w, r)
	if !ok {
		return
	}

	if sess.MustChange {
		http.Redirect(w, r, "/change-password", http.StatusSeeOther)
		return
	}

	user, err := a.Store.GetUser(sess.Username)
	if err != nil {
		minimalResponse(w)
		return
	}

	web.Render(w, "app.html", templateData{
		Username:          user.Username,
		PasswordChangedAt: user.PasswordChangedAt.Format(time.RFC3339),
	})
}

func (a *App) changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		sess, ok := a.requireSession(w, r)
		if !ok {
			return
		}
		web.Render(w, "change_password.html", templateData{CSRFToken: sess.CSRFToken})
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	sess, ok := a.requireSession(w, r)
	if !ok {
		return
	}

	if !a.verifySessionCSRF(r, sess.CSRFToken) {
		minimalResponse(w)
		return
	}

	if err := r.ParseForm(); err != nil {
		minimalResponse(w)
		return
	}

	current := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if newPassword == "" || current == "" || confirm == "" {
		web.Render(w, "change_password.html", templateData{CSRFToken: sess.CSRFToken, Error: "All fields are required."})
		return
	}
	if newPassword != confirm {
		web.Render(w, "change_password.html", templateData{CSRFToken: sess.CSRFToken, Error: "Passwords do not match."})
		return
	}

	user, err := a.Store.GetUser(sess.Username)
	if err != nil {
		minimalResponse(w)
		return
	}

	okPassword, err := auth.VerifyPassword(current, user.PasswordHash)
	if err != nil || !okPassword {
		web.Render(w, "change_password.html", templateData{CSRFToken: sess.CSRFToken, Error: "Invalid current password."})
		return
	}

	if !checkPasswordComplexity(newPassword) {
		web.Render(w, "change_password.html", templateData{CSRFToken: sess.CSRFToken, Error: "Password does not meet complexity requirements."})
		return
	}

	if same, err := auth.VerifyPassword(newPassword, user.PasswordHash); err == nil && same {
		web.Render(w, "change_password.html", templateData{CSRFToken: sess.CSRFToken, Error: "New password must differ from old password."})
		return
	}

	newHash, err := auth.HashPassword(newPassword)
	if err != nil {
		minimalResponse(w)
		return
	}

	now := time.Now()
	if err := a.Store.UpdatePassword(user.Username, newHash, now); err != nil {
		minimalResponse(w)
		return
	}

	a.Sessions.Update(sess.ID, func(s *session.Session) {
		s.MustChange = false
		s.ExpiresAt = now.Add(sessionTTL)
	})

	http.Redirect(w, r, "/app", http.StatusSeeOther)
}

func (a *App) requireSession(w http.ResponseWriter, r *http.Request) (*session.Session, bool) {
	cookie, err := r.Cookie(a.CookieName)
	if err != nil || cookie.Value == "" {
		minimalResponse(w)
		return nil, false
	}

	sess, ok := a.Sessions.Get(cookie.Value, time.Now())
	if !ok {
		minimalResponse(w)
		return nil, false
	}

	return sess, true
}

func (a *App) renderLoginError(w http.ResponseWriter) {
	csrfToken, err := a.issueCSRFCookie(w)
	if err != nil {
		minimalResponse(w)
		return
	}
	web.Render(w, "index.html", templateData{CSRFToken: csrfToken, Error: "invalid"})
}

func (a *App) issueCSRFCookie(w http.ResponseWriter) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	setCSRFCookie(w, token)
	return token, nil
}

func (a *App) verifyCSRF(r *http.Request) bool {
	formToken := r.FormValue("csrf_token")
	if formToken == "" {
		formToken = r.Header.Get("X-CSRF-Token")
	}
	cookie, err := r.Cookie("csrf_token")
	if err != nil || cookie.Value == "" {
		return false
	}
	return cookie.Value == formToken
}

func (a *App) verifySessionCSRF(r *http.Request, token string) bool {
	if token == "" {
		return false
	}
	if err := r.ParseForm(); err != nil {
		return false
	}
	formToken := r.FormValue("csrf_token")
	cookie, err := r.Cookie("csrf_token")
	if err != nil || cookie.Value == "" {
		return false
	}
	return cookie.Value == formToken && token == formToken
}

func parseLoginRequest(r *http.Request) (*loginRequest, error) {
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		var payload loginRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			return nil, err
		}
		return &payload, nil
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return &loginRequest{
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
	}, nil
}

func checkPasswordComplexity(password string) bool {
	if len(password) < 12 {
		return false
	}

	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSymbol
}

func bootstrapMemoryUser(app *App) {
	memory, ok := app.Store.(*store.MemoryStore)
	if !ok {
		return
	}

	username := strings.TrimSpace(os.Getenv("BOOTSTRAP_USER"))
	if username == "" {
		return
	}

	var hash string
	if rawHash := strings.TrimSpace(os.Getenv("BOOTSTRAP_HASH")); rawHash != "" {
		hash = rawHash
	} else if password := os.Getenv("BOOTSTRAP_PASSWORD"); password != "" {
		generated, err := auth.HashPassword(password)
		if err != nil {
			log.Printf("bootstrap hash error: %v", err)
			return
		}
		hash = generated
	}

	if hash == "" {
		log.Printf("bootstrap user set without password/hash")
		return
	}

	memory.AddUser(username, hash, true, time.Now().UTC())
}

func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func minimalResponse(w http.ResponseWriter) {
	w.Header().Del("Server")
	w.WriteHeader(http.StatusNotFound)
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func setSessionCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func setCSRFCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    value,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
