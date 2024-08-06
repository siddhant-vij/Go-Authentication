package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sync"
)

func main() {
	http.HandleFunc("/auth", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

var (
	counter   = 0
	secrets   = make(map[string][]byte)
	secretsMu sync.Mutex
)

func handler(w http.ResponseWriter, r *http.Request) {
	message := []byte("Hello World!")

	if counter == 0 {
		// First request, generate new secret and set session
		secret, err := createSecret()
		if err != nil {
			http.Error(w, "Error generating secret", http.StatusInternalServerError)
			return
		}
		signature, err := signMessage(message, secret)
		if err != nil {
			http.Error(w, "Error signing message", http.StatusInternalServerError)
			return
		}

		// Create a unique session ID
		sessionID := createSessionID()
		secretsMu.Lock()
		secrets[sessionID] = secret // Store the secret by session ID
		secretsMu.Unlock()

		// Set cookies for signature and session ID
		http.SetCookie(w, &http.Cookie{
			Name:     "signature",
			Value:    encode(signature),
			Path:     "/",
			MaxAge:   3600,
			Secure:   true, // Use HTTPS
			HttpOnly: true,
			Domain:   "localhost",
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			MaxAge:   3600,
			Secure:   true, // Use HTTPS
			HttpOnly: true,
			Domain:   "localhost",
		})

		// Set counter to 1 - to check the signature in else clause
		counter++
	} else {
		// Subsequent request, verify signature
		signatureCookie, err := r.Cookie("signature")
		if err != nil {
			http.Error(w, "Signature not found", http.StatusUnauthorized)
			return
		}

		sessionID, err := r.Cookie("session_id")
		if err != nil {
			http.Error(w, "Session ID not found", http.StatusUnauthorized)
			return
		}

		secretsMu.Lock()
		secret, exists := secrets[sessionID.Value]
		// This way secret always stays on the server - could be expanded to keep it in a redis (with same age as that in the cookie)
		secretsMu.Unlock()

		if !exists {
			http.Error(w, "Session not found", http.StatusUnauthorized)
			return
		}

		signature := decode(signatureCookie.Value)
		ok, err := checkSignature(message, secret, signature)
		if err != nil || !ok {
			http.Error(w, "Authentication failed", http.StatusUnauthorized)
			return
		}

		w.Write([]byte("Authentication Successful\n"))
		w.Write([]byte("Message: " + string(message) + "\n"))
	}
}

// Generates a cryptographically secure random secret
func createSecret() ([]byte, error) {
	bs := make([]byte, 64) // blocksize of SHA256 in bytes.
	_, err := rand.Read(bs)
	if err != nil {
		return nil, err
	}
	return bs, nil
}

// Creates a unique session ID
func createSessionID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", b)
}

// Encodes a byte slice to a base64 string
func encode(signature []byte) string {
	return base64.StdEncoding.EncodeToString(signature)
}

// Decodes a base64 string to a byte slice
func decode(signature string) []byte {
	bs, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		panic(err)
	}
	return bs
}

// Signs a message with HMAC using SHA256
func signMessage(message, secret []byte) ([]byte, error) {
	hash := hmac.New(sha256.New, secret)
	_, err := hash.Write(message)
	if err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

// Checks if a given signature is valid for the message and secret
func checkSignature(message, secret, signature []byte) (bool, error) {
	newSign, err := signMessage(message, secret)
	if err != nil {
		return false, err
	}
	return hmac.Equal(newSign, signature), nil
}
