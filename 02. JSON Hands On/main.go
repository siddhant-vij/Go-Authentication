package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type Person struct {
	First string
}

func main() {
	http.HandleFunc("/encode", encode)
	http.HandleFunc("/decode", decode)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func encode(w http.ResponseWriter, r *http.Request) {
	xp := []Person{
		{First: "Jenny"},
		{First: "James"},
	}
	w.Header().Set("Content-Type", "application/json")
	encode := json.NewEncoder(w)
	err := encode.Encode(xp)
	if err != nil {
		log.Println(err)
	}
}

func decode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	decode := json.NewDecoder(r.Body)
	var people []Person
	err := decode.Decode(&people)
	if err != nil {
		log.Println(err)
	}
	for _, person := range people {
		fmt.Println(person.First)
	}
}

// curl -XPOST -d '[{"First":"Jenny"},{"First":"James"},{"First":"Test"}]' 'localhost:8080/decode'
