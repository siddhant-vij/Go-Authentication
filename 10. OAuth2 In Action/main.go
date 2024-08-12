package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
}

func main() {
	var state string
	cfg := &oauth2.Config{
		ClientID:     os.Getenv("GH_CLIENT_ID"),
		ClientSecret: os.Getenv("GH_CLIENT_SECRET"),
		Endpoint:     github.Endpoint,

		// RedirectURL:  os.Getenv("GH_REDIRECT_URL"),
		// Same as configured in OAuth Application settings in GitHub

		// Scopes:       []string{"read:user", "user:email"},
		// Left blank, read-only access to public info is granted
	}

	http.HandleFunc("/", serveHomePage)

	http.HandleFunc("/oauth/github", func(w http.ResponseWriter, r *http.Request) {
		state = gitHubAuthHandler(w, r, cfg)
	})

	http.HandleFunc("/github/callback", func(w http.ResponseWriter, r *http.Request) {
		client := gitHubCallbackHandler(w, r, cfg, state)
		getGitHubProfileForUser(w, r, client)
	})

	http.HandleFunc("/resource", serveResourcePage)

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func serveHomePage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "public/index.html")
}

func gitHubAuthHandler(w http.ResponseWriter, r *http.Request, cfg *oauth2.Config) string {
	// Generate a random state
	state := generateRandomState()

	// Redirect the user to the GitHub authorization URL
	http.Redirect(w, r, cfg.AuthCodeURL(state), http.StatusTemporaryRedirect)

	return state
}

func generateRandomState() string {
	bs := make([]byte, 32)
	_, err := rand.Read(bs)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(bs)
}

func gitHubCallbackHandler(w http.ResponseWriter, r *http.Request, cfg *oauth2.Config, state string) *http.Client {
	// Check the state from the request
	urlState := r.URL.Query().Get("state")
	if urlState != state {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return nil
	}

	// Get the code from the request
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return nil
	}

	// Exchange the code for an access token
	token, err := cfg.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}

	// Get the tokensource from the token
	ts := cfg.TokenSource(r.Context(), token)

	// Get the HTTP client with the tokensource
	return oauth2.NewClient(r.Context(), ts)
}

func getGitHubProfileForUser(w http.ResponseWriter, r *http.Request, client *http.Client) {
	// Get the GitHub profile
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Get the user's name
	var profile struct {
		Name        string `json:"login"`
		Picture     string `json:"avatar_url"`
		PublicRepos int    `json:"public_repos"`
	}
	err = json.NewDecoder(resp.Body).Decode(&profile)
	if err != nil {
		panic(err)
	}

	// create HTML file to serve
	tpl := template.Must(template.ParseFiles("templates/resource.gohtml"))

	file, err := os.Create("public/resource.html")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	err = tpl.Execute(file, profile)
	if err != nil {
		panic(err)
	}

	http.Redirect(w, r, "/resource", http.StatusTemporaryRedirect)
}

func serveResourcePage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "public/resource.html")
}
