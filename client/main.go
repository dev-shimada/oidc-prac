package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os/signal"
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

func generateCodeVerifier() string {
	const length = 43
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	// init random seed
	rand.New(rand.NewSource(time.Now().UnixNano()))
	// create a random string
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	return string(b)
}

var codeVerifier string

func login(w http.ResponseWriter, req *http.Request) {
	codeVerifier = generateCodeVerifier()
	endpoint := config.AuthCodeURL(
		"state",
		oauth2.S256ChallengeOption(codeVerifier),
		oauth2.SetAuthURLParam("client_id", config.ClientID),
		oauth2.SetAuthURLParam("response_type", "code id_token"),
		oauth2.SetAuthURLParam("scope", "openid profile email"),
	)
	slog.Info("Redirecting to OIDC provider for login", "endpoint", endpoint)
	http.Redirect(w, req, endpoint, http.StatusFound)
}

func callback(w http.ResponseWriter, req *http.Request) {
	slog.Info("Handling callback from OIDC provider")
	token, err := config.Exchange(
		ctx,
		req.FormValue("code"),
		oauth2.SetAuthURLParam("client_id", config.ClientID),
		// oauth2.SetAuthURLParam("client_secret", config.ClientSecret),
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
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

	fmt.Println("id_token:", token.Extra("id_token"))
	idToken := token.Extra("id_token").(string)
	if idToken == "" {
		http.Error(w, "ID Token is empty", http.StatusInternalServerError)
		return
	}
	slog.Info("ID Token", "token", idToken)

	if _, err := provider.Verifier(&oidc.Config{
		ClientID: "1234",
	}).Verify(ctx, idToken); err != nil {
		panic(err)
	}

	// userinfo
	userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil {
		http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	b := make([]byte, 0, 1024)
	w.Write(fmt.Appendf(b, "User Info: %v\n", userInfo))
}
