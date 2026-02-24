package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"safe_web/internal/auth"
	"safe_web/internal/ratelimit"
	"safe_web/internal/session"
	"safe_web/internal/store"
	"safe_web/internal/web"
)

const (
	defaultPublicAddr = ":8443"
	defaultAdminAddr  = "127.0.0.1:9443"
	defaultLocalAddr  = ""

	defaultPublicCertPath = "config/cert.pem"
	defaultPublicKeyPath  = "config/key.pem"
	defaultAdminCertPath  = "config/admin_cert.pem"
	defaultAdminKeyPath   = "config/admin_key.pem"

	loginWindowMinutes = 10
	banTTLMinutes      = 60
	maxLoginBodyBytes  = 1 << 20
	passwordMaxAge     = 90 * 24 * time.Hour
	publicSessionTTL   = 8 * time.Hour
	adminSessionTTL    = 2 * time.Hour
)

type App struct {
	Store         store.Store
	Limiter       *ratelimit.Limiter
	AdminLimiter  *ratelimit.Limiter
	Sessions      *session.Store
	AdminSessions *session.Store
	DummyHash     string
	CookieName    string
	AdminCookie   string
	Settings      *Settings
	AdminTLS      bool
}

type Settings struct {
	RequireLogin bool
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
	Clients           []store.Client
	Client            *store.Client
	WhitelistEntries  []store.WhitelistEntry
	Audit             []store.AuditEntry
	Settings          *Settings
	Users             []store.User
}

func main() {
	publicAddr := getenv("LISTEN_PUBLIC_ADDR", defaultPublicAddr)
	adminAddr := getenv("LISTEN_ADMIN_ADDR", defaultAdminAddr)
	localAddr := getenv("LISTEN_LOCAL_ADDR", defaultLocalAddr)
	publicCertPath := getenv("PUBLIC_CERT_PATH", defaultPublicCertPath)
	publicKeyPath := getenv("PUBLIC_KEY_PATH", defaultPublicKeyPath)
	adminCertPath := getenv("ADMIN_CERT_PATH", defaultAdminCertPath)
	adminKeyPath := getenv("ADMIN_KEY_PATH", defaultAdminKeyPath)
	adminTLSEnabled := getenvBool("ADMIN_TLS_ENABLED", false)
	requireLogin := getenvBool("REQUIRE_LOGIN", true)

	validateListenAddr(publicAddr)
	validateLoopbackAddr(adminAddr)

	st, err := store.NewStore()
	if err != nil {
		log.Fatalf("store init: %v", err)
	}

	dummyHash, err := auth.HashPassword("dummy-password")
	if err != nil {
		log.Fatalf("dummy hash: %v", err)
	}

	settings := &Settings{
		RequireLogin: requireLogin,
	}

	app := &App{
		Store:         st,
		Limiter:       ratelimit.New(5, time.Minute),
		AdminLimiter:  ratelimit.New(5, time.Minute),
		Sessions:      session.NewStore(publicSessionTTL),
		AdminSessions: session.NewStore(adminSessionTTL),
		DummyHash:     dummyHash,
		CookieName:    "session_id",
		AdminCookie:   "admin_session",
		Settings:      settings,
		AdminTLS:      adminTLSEnabled,
	}

	bootstrapAdminUser(app)

	publicTLS, err := buildPublicTLSConfig()
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}

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
		TLSConfig:         publicTLS,
	}

	adminMux := http.NewServeMux()
	adminMux.Handle("/", app.adminIPGuard(app.securityHeaders(http.HandlerFunc(app.adminRootHandler))))
	adminMux.Handle("/admin/login", app.adminIPGuard(app.securityHeaders(http.HandlerFunc(app.adminLoginHandler))))
	adminMux.Handle("/admin/logout", app.adminIPGuard(app.securityHeaders(http.HandlerFunc(app.adminLogoutHandler))))
	adminMux.Handle("/admin/dashboard", app.adminAuth(app.securityHeaders(http.HandlerFunc(app.adminDashboardHandler))))
	adminMux.Handle("/admin/clients", app.adminAuth(app.securityHeaders(http.HandlerFunc(app.adminClientsHandler))))
	adminMux.Handle("/admin/clients/", app.adminAuth(app.securityHeaders(http.HandlerFunc(app.adminClientDetailHandler))))
	adminMux.Handle("/admin/whitelist", app.adminAuth(app.securityHeaders(http.HandlerFunc(app.adminWhitelistHandler))))
	adminMux.Handle("/admin/settings", app.adminAuth(app.securityHeaders(http.HandlerFunc(app.adminSettingsHandler))))
	adminMux.Handle("/admin/audit", app.adminAuth(app.securityHeaders(http.HandlerFunc(app.adminAuditHandler))))

	adminServer := &http.Server{
		Addr:              adminAddr,
		Handler:           adminMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
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

	go func() {
		log.Printf("admin listening on %s", adminAddr)
		if adminTLSEnabled {
			if err := adminServer.ListenAndServeTLS(adminCertPath, adminKeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("admin server error: %v", err)
			}
			return
		}
		if err := adminServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("admin server error: %v", err)
		}
	}()

	log.Printf("public https listening on %s", publicAddr)
	if err := publicServer.ListenAndServeTLS(publicCertPath, publicKeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("public server error: %v", err)
	}
}

func buildPublicTLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}
	return cfg, nil
}

func (a *App) ipGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if ip == nil {
			minimalResponse(w)
			return
		}
		allowed, err := a.isWhitelisted(ip.String())
		if err != nil || !allowed {
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

func (a *App) adminIPGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if ip == nil || !ip.IsLoopback() {
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

	setSessionCookie(w, a.CookieName, sess.ID, true)
	setCSRFCookie(w, sess.CSRFToken, true)

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
		if a.Settings.RequireLogin {
			return
		}
		web.Render(w, "app.html", templateData{Username: "device"})
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
		s.ExpiresAt = now.Add(publicSessionTTL)
	})

	http.Redirect(w, r, "/app", http.StatusSeeOther)
}

func (a *App) adminLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		csrf, err := a.issueAdminCSRFCookie(w)
		if err != nil {
			minimalResponse(w)
			return
		}
		web.Render(w, "admin_login.html", templateData{CSRFToken: csrf})
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ip := clientIP(r)
	if ip == nil {
		minimalResponse(w)
		return
	}

	if !a.AdminLimiter.Allow(ip.String(), time.Now()) {
		minimalResponse(w)
		return
	}

	if !a.verifyAdminCSRF(r) {
		minimalResponse(w)
		return
	}

	if err := r.ParseForm(); err != nil {
		minimalResponse(w)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	if username == "" || password == "" {
		web.Render(w, "admin_login.html", templateData{CSRFToken: a.rotateAdminCSRF(w), Error: "Invalid credentials."})
		return
	}

	admin, err := a.Store.GetAdminUser(username)
	storedHash := a.DummyHash
	if err == nil {
		storedHash = admin.PasswordHash
	}
	ok, verifyErr := auth.VerifyPassword(password, storedHash)
	if verifyErr != nil || err != nil || !ok {
		web.Render(w, "admin_login.html", templateData{CSRFToken: a.rotateAdminCSRF(w), Error: "Invalid credentials."})
		return
	}

	_ = a.Store.UpdateAdminLogin(username, time.Now())
	sess, err := a.AdminSessions.Create(username, false, time.Now())
	if err != nil {
		minimalResponse(w)
		return
	}

	setSessionCookie(w, a.AdminCookie, sess.ID, a.AdminTLS)
	setCSRFCookie(w, sess.CSRFToken, a.AdminTLS)
	_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: username, Action: "admin_login", TargetType: "admin", TargetID: username, Metadata: "{}", CreatedAt: time.Now()})
	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

func (a *App) adminRootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (a *App) adminLogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(a.AdminCookie)
	if err == nil {
		a.AdminSessions.Delete(cookie.Value)
	}
	setSessionCookie(w, a.AdminCookie, "", a.AdminTLS)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (a *App) adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	web.Render(w, "admin_dashboard.html", templateData{})
}

func (a *App) adminClientsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !a.verifyAdminCSRF(r) {
			minimalResponse(w)
			return
		}
		if err := r.ParseForm(); err != nil {
			minimalResponse(w)
			return
		}
		name := strings.TrimSpace(r.FormValue("name"))
		if name != "" {
			client, err := a.Store.CreateClient(name, time.Now())
			if err == nil {
				_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: a.adminActor(r), Action: "client_create", TargetType: "client", TargetID: fmt.Sprintf("%d", client.ID), Metadata: "{}", CreatedAt: time.Now()})
			}
		}
		http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
		return
	}

	clients, _ := a.Store.ListClients()
	csrf := a.rotateAdminCSRF(w)
	web.Render(w, "admin_clients.html", templateData{Clients: clients, CSRFToken: csrf})
}

func (a *App) adminClientDetailHandler(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(strings.TrimPrefix(r.URL.Path, "/admin/clients/"))
	if err != nil {
		minimalResponse(w)
		return
	}

	client, err := a.Store.GetClient(id)
	if err != nil {
		minimalResponse(w)
		return
	}

	if r.Method == http.MethodPost {
		if !a.verifyAdminCSRF(r) {
			minimalResponse(w)
			return
		}
		if err := r.ParseForm(); err != nil {
			minimalResponse(w)
			return
		}
		action := r.FormValue("action")
		switch action {
		case "disable":
			_ = a.Store.SetClientStatus(id, "disabled", time.Now())
			_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: a.adminActor(r), Action: "client_disable", TargetType: "client", TargetID: fmt.Sprintf("%d", id), Metadata: "{}", CreatedAt: time.Now()})
		case "enable":
			_ = a.Store.SetClientStatus(id, "active", time.Now())
			_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: a.adminActor(r), Action: "client_enable", TargetType: "client", TargetID: fmt.Sprintf("%d", id), Metadata: "{}", CreatedAt: time.Now()})
		case "create_user":
			username := strings.TrimSpace(r.FormValue("username"))
			password := r.FormValue("password")
			ip := strings.TrimSpace(r.FormValue("ip"))
			if username == "" || password == "" || !validateWhitelistValue(ip) {
				http.Redirect(w, r, fmt.Sprintf("/admin/clients/%d", id), http.StatusSeeOther)
				return
			}
			hash, err := auth.HashPassword(password)
			if err == nil {
				if user, err := a.Store.CreateUser(id, username, hash, time.Now()); err == nil {
					_ = a.Store.AddWhitelist(store.WhitelistEntry{
						Value:     ip,
						OwnerType: "user",
						OwnerID:   user.ID,
						Label:     username,
						CreatedAt: time.Now(),
					})
					_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: a.adminActor(r), Action: "user_create", TargetType: "user", TargetID: fmt.Sprintf("%d", user.ID), Metadata: "{}", CreatedAt: time.Now()})
				}
			}
		}
		http.Redirect(w, r, fmt.Sprintf("/admin/clients/%d", id), http.StatusSeeOther)
		return
	}

	users, _ := a.Store.ListUsersByClient(id)
	csrf := a.rotateAdminCSRF(w)
	web.Render(w, "admin_client_detail.html", templateData{Client: client, Users: users, CSRFToken: csrf})
}

func (a *App) adminWhitelistHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !a.verifyAdminCSRF(r) {
			minimalResponse(w)
			return
		}
		if err := r.ParseForm(); err != nil {
			minimalResponse(w)
			return
		}
		entry := strings.TrimSpace(r.FormValue("entry"))
		label := strings.TrimSpace(r.FormValue("label"))
		if entry != "" && validateWhitelistValue(entry) {
			_ = a.Store.AddWhitelist(store.WhitelistEntry{
				Value:     entry,
				OwnerType: "manual",
				OwnerID:   0,
				Label:     label,
				CreatedAt: time.Now(),
			})
			_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: a.adminActor(r), Action: "whitelist_add", TargetType: "whitelist", TargetID: entry, Metadata: "{}", CreatedAt: time.Now()})
		}
		if deleteID := r.FormValue("delete_id"); deleteID != "" {
			if id, err := strconv.ParseInt(deleteID, 10, 64); err == nil {
				_ = a.Store.DeleteWhitelist(id)
				_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: a.adminActor(r), Action: "whitelist_delete", TargetType: "whitelist", TargetID: deleteID, Metadata: "{}", CreatedAt: time.Now()})
			}
		}
		http.Redirect(w, r, "/admin/whitelist", http.StatusSeeOther)
		return
	}

	entries, _ := a.Store.ListWhitelist()
	csrf := a.rotateAdminCSRF(w)
	web.Render(w, "admin_whitelist.html", templateData{WhitelistEntries: entries, CSRFToken: csrf})
}

func (a *App) adminSettingsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !a.verifyAdminCSRF(r) {
			minimalResponse(w)
			return
		}
		if err := r.ParseForm(); err != nil {
			minimalResponse(w)
			return
		}
		a.Settings.RequireLogin = r.FormValue("require_login") == "on"
		_ = a.Store.InsertAuditEntry(store.AuditEntry{Actor: a.adminActor(r), Action: "settings_update", TargetType: "settings", TargetID: "global", Metadata: "{}", CreatedAt: time.Now()})
		http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
		return
	}

	csrf := a.rotateAdminCSRF(w)
	web.Render(w, "admin_settings.html", templateData{Settings: a.Settings, CSRFToken: csrf})
}

func (a *App) adminAuditHandler(w http.ResponseWriter, r *http.Request) {
	entries, _ := a.Store.ListAudit(100)
	csrf := a.rotateAdminCSRF(w)
	web.Render(w, "admin_audit.html", templateData{Audit: entries, CSRFToken: csrf})
}

func (a *App) adminAuth(next http.Handler) http.Handler {
	return a.adminIPGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin/login") {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(a.AdminCookie)
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		sess, ok := a.AdminSessions.Get(cookie.Value, time.Now())
		if !ok {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		_ = sess
		next.ServeHTTP(w, r)
	}))
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
	setCSRFCookie(w, token, true)
	return token, nil
}

func (a *App) issueAdminCSRFCookie(w http.ResponseWriter) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	setCSRFCookie(w, token, a.AdminTLS)
	return token, nil
}

func (a *App) rotateAdminCSRF(w http.ResponseWriter) string {
	token, err := randomToken(32)
	if err != nil {
		return ""
	}
	setCSRFCookie(w, token, a.AdminTLS)
	return token
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

func (a *App) verifyAdminCSRF(r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		return false
	}
	formToken := r.FormValue("csrf_token")
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

func bootstrapAdminUser(app *App) {
	memory, ok := app.Store.(*store.MemoryStore)
	if !ok {
		return
	}
	username := strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_USER"))
	password := os.Getenv("BOOTSTRAP_ADMIN_PASSWORD")
	if username == "" || password == "" {
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return
	}
	memory.AddAdminUser(username, hash, "admin", time.Now())
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

func setSessionCookie(w http.ResponseWriter, name, value string, secure bool) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	if value == "" {
		cookie.MaxAge = -1
	}
	http.SetCookie(w, cookie)
}

func setCSRFCookie(w http.ResponseWriter, value string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    value,
		Path:     "/",
		Secure:   secure,
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

func getenvBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func validateListenAddr(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		log.Fatalf("invalid LISTEN_PUBLIC_ADDR: %v", err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatalf("interfaces: %v", err)
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.String() == host {
			return
		}
	}
	log.Fatalf("LISTEN_PUBLIC_ADDR host %s not found on any interface", host)
}

func validateLoopbackAddr(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		log.Fatalf("invalid LISTEN_ADMIN_ADDR: %v", err)
	}
	if host == "" {
		return
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		log.Fatalf("LISTEN_ADMIN_ADDR must be loopback (127.0.0.1 or ::1)")
	}
}
