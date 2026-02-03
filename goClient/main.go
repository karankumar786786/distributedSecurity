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

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var (
	oauthConfig *oauth2.Config
	issuer      string
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	issuer = os.Getenv("ISSUER_URL")
	oauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URI"),
		Scopes:       []string{"openid", "profile", "read"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  issuer + "/oauth2/authorize",
			TokenURL: issuer + "/oauth2/token",
		},
	}
}

// PKCE helpers
func generateVerifier() string {
	b := make([]byte, 32)
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
		fmt.Fprintf(w, "<h1>Home</h1><a href='/login'>Login with OAuth2</a>")
		return
	}

	fmt.Fprintf(w, "<h1>Welcome</h1><p>Session: %s</p><a href='/logout'>Logout</a>", cookie.Value)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	verifier := generateVerifier()
	challenge := generateChallenge(verifier)
	state := generateVerifier() // misuse helper for simplicity
	nonce := generateVerifier()

	// Store PKCE and OIDC params in cookies
	setCookie(w, "go_cv", verifier)
	setCookie(w, "go_state", state)
	setCookie(w, "go_nonce", nonce)

	url := oauthConfig.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.S256ChallengeOption(challenge),
		oauth2.SetAuthURLParam("nonce", nonce),
	)
	http.Redirect(w, r, url, http.StatusFound)
}

func setCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Error(w, "Missing code or state", http.StatusBadRequest)
		return
	}

	// Verify state
	stateCookie, err := r.Cookie("go_state")
	if err != nil || stateCookie.Value != state {
		http.Error(w, "State mismatch", http.StatusForbidden)
		return
	}

	cvCookie, err := r.Cookie("go_cv")
	if err != nil {
		http.Error(w, "No verifier found", http.StatusForbidden)
		return
	}

	fmt.Printf("Exchanging code: %s with verifier: %s\n", code, cvCookie.Value)

	token, err := oauthConfig.Exchange(context.Background(), code, oauth2.VerifierOption(cvCookie.Value))
	if err != nil {
		fmt.Printf("Token exchange error: %v\n", err)
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("Successfully exchanged token. AccessToken: %s...\n", token.AccessToken[:10])

	// Store token in session (simplified)
	setCookie(w, "go_session", token.AccessToken[:10]+"...")

	// Clear temporary cookies
	clearCookie(w, "go_cv")
	clearCookie(w, "go_state")
	clearCookie(w, "go_nonce")

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
	http.SetCookie(w, &http.Cookie{
		Name:   "go_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}
