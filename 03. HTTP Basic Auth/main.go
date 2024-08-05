package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
)

func main() {
	http.HandleFunc("/auth", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handler(w http.ResponseWriter, r *http.Request) {
	// BasicAuth returns the username and password provided in the request's Authorization header, if the request uses HTTP Basic Authentication.
	user, pass, ok := r.BasicAuth()
	if !ok || user != "username" || pass != "password" {
		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		w.WriteHeader(401)
		w.Write([]byte("Unauthorised\n"))
		return
	}
	w.Write([]byte("Hello World!\n"))

	// base64 converted value for username:password
	fmt.Println(base64.StdEncoding.EncodeToString([]byte("username:password")))

	// Authorization header with the curl request (below)
	fmt.Println(strings.Split(r.Header.Get("Authorization"), " ")[1])
}

// Curl Request
// curl -v -u 'username:password' 'localhost:8080/auth'
// This can also be done with the type Request (that's client side code) using SetBasicAuth(username, password)

// What's passed to BasicAuth is base64 encoded.
// base64.StdEncoding.EncodeToString([]byte("username:password"))

// base64 is reversible
// never use with http; only https
// use basic authentication only to login - and that too along with 2FA (not on all endpoints)

// Cons of using BasicAuth
// With every request?
// Is this secure?
