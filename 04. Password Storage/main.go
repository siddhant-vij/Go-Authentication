package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/bcrypt"
)

type user struct {
	Username string
	Hash     string
}

func main() {
	http.HandleFunc("/auth", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// curl -u 'username:password' 'localhost:8080/auth'

func handler(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Write([]byte("Unauthorised\n"))
		return
	}

	users := loadUsersFromFile("users.json")
	userExists := false
	for _, u := range users {
		if u.Username == username {
			userExists = true
			if checkPasswordHash([]byte(password), []byte(u.Hash)) {
				w.Write([]byte("Authentication Successful\n"))
				return
			} else {
				w.Write([]byte("Password Incorrect\n"))
				return
			}
		}
	}

	if !userExists {
		w.Write([]byte("User does not exist. Adding user to DB.\n"))

		users = append(users, user{username, hashPassword([]byte(password))})
		saveUsersToFile(users, "users.json")
	}
}

func saveUsersToFile(users []user, fileName string) {
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	err = encoder.Encode(users)
	if err != nil {
		log.Fatal(err)
	}
}

func loadUsersFromFile(fileName string) []user {
	file, err := os.OpenFile(fileName, os.O_RDONLY, 0644)
	if os.IsNotExist(err) {
		return []user{}
	}
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var users []user
	err = json.NewDecoder(file).Decode(&users)
	if err != nil {
		log.Fatal(err)
	}
	return users
}

func hashPassword(password []byte) string {
	// GenerateFromPassword returns the bcrypt hash of the password at the given cost.
	// password is the password to hash. Should be less that 72 bytes long.
	bs, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	return string(bs)
}

func checkPasswordHash(password, hash []byte) bool {
	// CompareHashAndPassword compares a bcrypt hashed password with its possible plaintext equivalent.
	err := bcrypt.CompareHashAndPassword(hash, password)
	return err == nil
}
