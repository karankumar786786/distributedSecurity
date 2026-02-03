package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var (
	oauthConfig *oauth2.Config
	provider    *oidc.Provider
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	ctx := context.Background()
	issuer := os.Getenv("ISSUER_URL")

	// Discover provider
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatalf("Failed to discover provider: %v", err)
	}
	provider = p

	oauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URI"),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "read"},
		Endpoint:     provider.Endpoint(),
	}
}

// PKCE helpers
func generateRandom(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/code/callback", handleCallback)
	http.HandleFunc("/logout", handleLogout)

	port := os.Getenv("PORT")
	if port == "" {
		port = "7800"
	}

	fmt.Printf("Go Client listening at http://127.0.0.1:%s\n", port)
	// Bind to 127.0.0.1 specifically to match the redirect URI
	log.Fatal(http.ListenAndServe("127.0.0.1:"+port, nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("go_session")
	if err != nil {
		fmt.Fprintf(w, "<html><body><h1>Go Client</h1><a href='/login'>Login with OAuth2</a></body></html>")
		return
	}
	fmt.Fprintf(w, "<html><body><h1>Welcome</h1><p>SID: %s</p><a href='/logout'>Logout</a></body></html>", cookie.Value)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state := generateRandom(32)
	nonce := generateRandom(32)
	verifier := generateRandom(32)
	challenge := generateChallenge(verifier)

	// Log for debugging
	fmt.Printf("[LOGIN] State: %s, Nonce: %s, Verifier: %s, Challenge: %s\n", state, nonce, verifier, challenge)

	setCookie(w, "go_state", state)
	setCookie(w, "go_nonce", nonce)
	setCookie(w, "go_cv", verifier)

	url := oauthConfig.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oidc.Nonce(nonce),
	)
	fmt.Printf("[LOGIN] Redirecting to: %s\n", url)
	http.Redirect(w, r, url, http.StatusFound)
}

func setCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in production
		SameSite: http.SameSiteLaxMode,
	})
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	fmt.Printf("[CALLBACK] Received Code: %s, State: %s\n", code, state)

	// Verify state
	stateCookie, err := r.Cookie("go_state")
	if err != nil {
		fmt.Printf("[ERROR] go_state cookie missing\n")
		http.Error(w, "State cookie missing", http.StatusBadRequest)
		return
	}
	if stateCookie.Value != state {
		fmt.Printf("[ERROR] State mismatch. Expected %s, got %s\n", stateCookie.Value, state)
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	// Get verifier
	cvCookie, err := r.Cookie("go_cv")
	if err != nil {
		fmt.Printf("[ERROR] go_cv cookie missing\n")
		http.Error(w, "Verifier missing", http.StatusBadRequest)
		return
	}

	fmt.Printf("[CALLBACK] Using Verifier: %s to exchange code\n", cvCookie.Value)

	// Exchange token
	token, err := oauthConfig.Exchange(ctx, code, oauth2.VerifierOption(cvCookie.Value))
	if err != nil {
		fmt.Printf("[ERROR] Token exchange failed: %v\n", err)
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Verify ID Token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		fmt.Printf("[ERROR] No id_token in token response\n")
		http.Error(w, "No id_token", http.StatusInternalServerError)
		return
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: oauthConfig.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		fmt.Printf("[ERROR] ID Token verification failed: %v\n", err)
		http.Error(w, "Failed to verify ID Token", http.StatusInternalServerError)
		return
	}

	// Verify nonce
	nonceCookie, err := r.Cookie("go_nonce")
	if err != nil || idToken.Nonce != nonceCookie.Value {
		fmt.Printf("[ERROR] Nonce mismatch. Expected %s, got %s\n", nonceCookie.Value, idToken.Nonce)
		http.Error(w, "Nonce mismatch", http.StatusBadRequest)
		return
	}

	fmt.Printf("[SUCCESS] User %s authenticated\n", idToken.Subject)

	setCookie(w, "go_session", idToken.Subject)
	clearCookie(w, "go_state")
	clearCookie(w, "go_nonce")
	clearCookie(w, "go_cv")

	http.Redirect(w, r, "/", http.StatusFound)
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	clearCookie(w, "go_session")
	http.Redirect(w, r, "/", http.StatusFound)
}
