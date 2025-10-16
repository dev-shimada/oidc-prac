package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	mathrand "math/rand"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	provider *oidc.Provider
	config   oauth2.Config
	ctx      = context.Background()
)

func main() {
	var err error
	provider, err = oidc.NewProvider(ctx, "http://localhost:49151")
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to create OIDC provider: %v", err))
		return
	}
	config = oauth2.Config{
		ClientID:     "1234",
		ClientSecret: "secret",
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:49150/callback",
		Scopes:       []string{oidc.ScopeOpenID},
	}

	// Start session cleanup goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			sessionStore.Cleanup()
			slog.Info("Session cleanup completed")
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/callback", callback)

	// Wait here until CTRL+C or other term signal is received
	srvCtx, _ := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	// defer stop()

	srv := &http.Server{
		Addr:    ":49150",
		Handler: mux,
	}

	slog.Info("Server is running at :49150 Press CTRL-C to exit.")
	go srv.ListenAndServe()

	<-srvCtx.Done()

	srvCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(srvCtx); err != nil {
		slog.Error(fmt.Sprintf("Failed to shutdown server: %v", err))
	}
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// generateState generates a cryptographically secure state parameter (CSRF protection)
func generateState() (string, error) {
	return generateRandomString(32)
}

// generateNonce generates a cryptographically secure nonce parameter (replay attack protection)
func generateNonce() (string, error) {
	return generateRandomString(32)
}

func generateCodeVerifier() string {
	const length = 43
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	// init random seed
	r := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	// create a random string
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}

	return string(b)
}

// Session storage for state and nonce validation
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]SessionData
}

type SessionData struct {
	State        string
	Nonce        string
	CodeVerifier string
	CreatedAt    time.Time
}

var sessionStore = &SessionStore{
	sessions: make(map[string]SessionData),
}

func (s *SessionStore) Set(sessionID string, data SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data.CreatedAt = time.Now()
	s.sessions[sessionID] = data
}

func (s *SessionStore) Get(sessionID string) (SessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, exists := s.sessions[sessionID]
	return data, exists
}

func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// Cleanup old sessions (older than 10 minutes)
func (s *SessionStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-10 * time.Minute)
	for id, data := range s.sessions {
		if data.CreatedAt.Before(cutoff) {
			delete(s.sessions, id)
		}
	}
}

func login(w http.ResponseWriter, req *http.Request) {
	// Generate cryptographically secure parameters
	state, err := generateState()
	if err != nil {
		slog.Error("Failed to generate state", "error", err)
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	nonce, err := generateNonce()
	if err != nil {
		slog.Error("Failed to generate nonce", "error", err)
		http.Error(w, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}

	codeVerifier := generateCodeVerifier()

	// Create session cookie
	sessionID, err := generateRandomString(16)
	if err != nil {
		slog.Error("Failed to generate session ID", "error", err)
		http.Error(w, "Failed to generate session ID", http.StatusInternalServerError)
		return
	}

	// Store session data
	sessionStore.Set(sessionID, SessionData{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
	})

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})

	slog.Info("Generated OIDC parameters", "state", state, "nonce", nonce, "sessionID", sessionID)

	endpoint := config.AuthCodeURL(
		state, // Use generated state
		oauth2.S256ChallengeOption(codeVerifier),
		oauth2.SetAuthURLParam("client_id", config.ClientID),
		oauth2.SetAuthURLParam("response_type", "code id_token"),
		oauth2.SetAuthURLParam("scope", "openid profile email"),
		oauth2.SetAuthURLParam("nonce", nonce), // Add nonce parameter
	)
	slog.Info("Redirecting to OIDC provider for login", "endpoint", endpoint)
	http.Redirect(w, req, endpoint, http.StatusFound)
}

func callback(w http.ResponseWriter, req *http.Request) {
	slog.Info("Handling callback from OIDC provider")

	// Get session cookie
	cookie, err := req.Cookie("oidc_session")
	if err != nil {
		slog.Error("Session cookie not found", "error", err)
		http.Error(w, "Session cookie not found", http.StatusBadRequest)
		return
	}

	// Retrieve session data
	sessionData, exists := sessionStore.Get(cookie.Value)
	if !exists {
		slog.Error("Session not found", "sessionID", cookie.Value)
		http.Error(w, "Session not found or expired", http.StatusBadRequest)
		return
	}

	// Validate state parameter (CSRF protection)
	returnedState := req.URL.Query().Get("state")
	if returnedState == "" {
		slog.Error("State parameter missing in callback")
		http.Error(w, "State parameter missing", http.StatusBadRequest)
		return
	}

	if returnedState != sessionData.State {
		slog.Error("State mismatch", "expected", sessionData.State, "got", returnedState)
		http.Error(w, "State mismatch - possible CSRF attack", http.StatusBadRequest)
		return
	}
	slog.Info("State validation successful", "state", returnedState)

	// Exchange authorization code for token
	token, err := config.Exchange(
		ctx,
		req.URL.Query().Get("code"),
		oauth2.SetAuthURLParam("client_id", config.ClientID),
		oauth2.SetAuthURLParam("code_verifier", sessionData.CodeVerifier),
	)
	if err != nil {
		slog.Error("Failed to exchange code for token", "error", err)
		http.Error(w, "Failed to exchange code for token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if token == nil {
		slog.Error("Token is nil")
		http.Error(w, "Token is nil", http.StatusInternalServerError)
		return
	}
	if !token.Valid() {
		slog.Error("Token is invalid", "token", token)
		http.Error(w, "Token is invalid", http.StatusInternalServerError)
		return
	}
	slog.Info("Token is valid", "token", token)

	// Extract ID Token
	fmt.Println("id_token:", token.Extra("id_token"))
	idTokenRaw := token.Extra("id_token")
	if idTokenRaw == nil {
		http.Error(w, "ID Token is missing", http.StatusInternalServerError)
		return
	}
	idTokenString := idTokenRaw.(string)
	if idTokenString == "" {
		http.Error(w, "ID Token is empty", http.StatusInternalServerError)
		return
	}
	slog.Info("ID Token received", "token", idTokenString)

	// Verify ID Token with nonce validation
	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})
	idToken, err := verifier.Verify(ctx, idTokenString)
	if err != nil {
		slog.Error("Failed to verify ID token", "error", err)
		http.Error(w, "Failed to verify ID token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	slog.Info("ID Token signature verified")

	// Extract and validate nonce claim (replay attack protection)
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := idToken.Claims(&claims); err != nil {
		slog.Error("Failed to parse ID token claims", "error", err)
		http.Error(w, "Failed to parse ID token claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if claims.Nonce == "" {
		slog.Warn("Nonce claim is missing in ID token")
	} else if claims.Nonce != sessionData.Nonce {
		slog.Error("Nonce mismatch", "expected", sessionData.Nonce, "got", claims.Nonce)
		http.Error(w, "Nonce mismatch - possible replay attack", http.StatusBadRequest)
		return
	} else {
		slog.Info("Nonce validation successful", "nonce", claims.Nonce)
	}

	// Clean up session after successful validation
	sessionStore.Delete(cookie.Value)
	http.SetCookie(w, &http.Cookie{
		Name:   "oidc_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	// Get userinfo
	userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	b := make([]byte, 0, 1024)
	w.Write(fmt.Appendf(b, "User Info: %+v\n", userInfo))
	slog.Info("Authentication successful", "subject", idToken.Subject)
}
