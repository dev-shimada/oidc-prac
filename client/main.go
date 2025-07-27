package main

import (
	"context"
	"fmt"
	"log"
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
	config   *oauth2.Config
	ctx      = context.Background()
)

func main() {
	var err error
	provider, err = oidc.NewProvider(ctx, "http://localhost:8081")
	if err != nil {
		log.Fatalf("Failed to create provider: %v", err)
	}
	config = &oauth2.Config{
		ClientID:     "1234",
		ClientSecret: "secret",
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:8080/callback",
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
		Addr:    ":8080",
		Handler: mux,
	}

	log.Println("Server is running at :8080 Press CTRL-C to exit.")
	go srv.ListenAndServe()

	<-srvCtx.Done()

	srvCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(srvCtx); err != nil {
		log.Printf("HTTP server Shutdown: %v", err)
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

func login(w http.ResponseWriter, req *http.Request) {
	endpoint := config.AuthCodeURL("state", oauth2.S256ChallengeOption(generateCodeVerifier()))
	http.Redirect(w, req, endpoint, http.StatusFound)
}

func callback(w http.ResponseWriter, req *http.Request) {
	token, err := config.Exchange(ctx, "code")
	if err != nil {
		http.Error(w, "Failed to exchange code for token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if token == nil {
		http.Error(w, "Token is nil", http.StatusInternalServerError)
		return
	}
	if !token.Valid() {
		http.Error(w, "Token is invalid", http.StatusInternalServerError)
		return
	}
	log.Printf("Access Token: %s", token.AccessToken)

	idToken := token.Extra("id_token").(string)
	if idToken == "" {
		http.Error(w, "ID Token is empty", http.StatusInternalServerError)
		return
	}
	log.Printf("ID Token: %s", idToken)

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
