// Implementation Flow: https://excalidraw.com/#json=YIDfDGUcg0VFjqIiO9Tp-,OmKY92L5KN0R3hxn4SCNiQ

package main

import (
	"crypto/rand"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	tpl    *template.Template
	secret []byte
)

const (
	accessTokenDuration  = 15 * time.Minute
	refreshTokenDuration = 7 * 24 * time.Hour
)

func init() {
	tpl = template.Must(template.ParseFiles("templates/resource.gohtml"))
	secret, _ = createSecret()
}

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/resource", resourceHandler)
	http.ListenAndServe(":8080", nil)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "public/index.html")
}

func resourceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// POST request comes from the login page only
		username := r.FormValue("username")
		password := r.FormValue("password")
		if username == "" || password == "" {
			http.Error(w, "Username or password cannot be empty", http.StatusBadRequest)
			return
		}

		// Generate access token on successful login & set the cookie
		atDetails, err := CreateToken(username, secret, accessTokenDuration)
		if err != nil {
			http.Error(w, "Error generating access token", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    atDetails.Token,
			Path:     "/",
			MaxAge:   int(accessTokenDuration.Seconds()),
			HttpOnly: true,
			Secure:   false,
		})

		// Generate refresh token on successful login & set the cookie
		rtDetails, err := CreateToken(username, secret, refreshTokenDuration)
		if err != nil {
			http.Error(w, "Error generating refresh token", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    rtDetails.Token,
			Path:     "/",
			MaxAge:   int(refreshTokenDuration.Seconds()),
			HttpOnly: true,
			Secure:   false,
		})

		// Serve the resource
		serveResource(w, r, username)
		return
	}

	// For GET requests, follow the implementation flow.
	atCookie, errAtPresent := r.Cookie("access_token")
	if errAtPresent == nil {
		aTokenStr := atCookie.Value
		aToken, errAtValid := ValidateToken(aTokenStr, secret)
		if errAtValid == nil {
			serveResource(w, r, aToken.Username)
			return
		}
	}

	rtCookie, errRtPresent := r.Cookie("refresh_token")
	if errRtPresent != nil {
		serveLogin(w, r)
		return
	}
	rTokenStr := rtCookie.Value
	rToken, errRtValid := ValidateToken(rTokenStr, secret)
	if errRtValid != nil {
		serveLogin(w, r)
		return
	}

	// Generate new access token (if refresh token is present & valid) & set the cookie
	atDetails, err := CreateToken(rToken.Username, secret, accessTokenDuration)
	if err != nil {
		http.Error(w, "Error generating access token from refresh token", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    atDetails.Token,
		Path:     "/",
		MaxAge:   int(accessTokenDuration.Seconds()),
		HttpOnly: true,
		Secure:   false,
	})

	// Serve the resource
	serveResource(w, r, rToken.Username)
}

func serveResource(w http.ResponseWriter, r *http.Request, username string) {
	file, err := os.Create("public/resource.html")
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	err = tpl.Execute(file, username)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.ServeFile(w, r, "public/resource.html")
}

func serveLogin(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "public/login.html")
}

func createSecret() ([]byte, error) {
	bs := make([]byte, 64) // blocksize of SHA256 in bytes.
	_, err := rand.Read(bs)
	if err != nil {
		return nil, err
	}
	return bs, nil
}

type TokenDetails struct {
	Token     string
	Username  string
	ExpiresIn int64
}

func CreateToken(username string, key []byte, ttl time.Duration) (TokenDetails, error) {
	if username == "" {
		return TokenDetails{}, fmt.Errorf("username cannot be empty")
	}
	if key == nil {
		return TokenDetails{}, fmt.Errorf("key cannot be empty")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"Issuer":    "jwt-demo",
		"IssuedAt":  jwt.NewNumericDate(time.Now()),
		"ExpiresAt": jwt.NewNumericDate(time.Now().Add(ttl)),
		"Subject":   username,
	})

	tokenString, err := token.SignedString([]byte(key))
	if err != nil {
		return TokenDetails{}, err
	}

	return TokenDetails{
		Token:     tokenString,
		Username:  username,
		ExpiresIn: int64(ttl.Seconds()),
	}, nil
}

func ValidateToken(tokenStr string, key []byte) (TokenDetails, error) {
	if tokenStr == "" {
		return TokenDetails{}, fmt.Errorf("token string cannot be empty")
	}
	if key == nil {
		return TokenDetails{}, fmt.Errorf("key cannot be empty")
	}
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return TokenDetails{}, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		expiresInDiff := int64(claims["ExpiresAt"].(float64) - float64(time.Now().Unix()))
		if expiresInDiff < 0 {
			return TokenDetails{}, fmt.Errorf("token has expired")
		}

		return TokenDetails{
			Token:     tokenStr,
			Username:  claims["Subject"].(string),
			ExpiresIn: expiresInDiff,
		}, nil
	}

	return TokenDetails{}, fmt.Errorf("invalid token")
}
