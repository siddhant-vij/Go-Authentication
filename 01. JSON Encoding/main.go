package main

import (
	"JSON_Encoding/decode"
	"JSON_Encoding/encode"
	"JSON_Encoding/marshal"
	"JSON_Encoding/unmarshal"
	"fmt"
	"os"
	"strings"
)

type Course struct {
	Title   string
	Price   int
	Website string
	Tags    []string
}

func (c Course) String() string {
	return fmt.Sprintf("Title: %s,\nPrice: %d,\nWebsite: %s,\nTags: %v\n", c.Title, c.Price, c.Website, c.Tags)
}

func main() {
	c1 := Course{
		Title:   "Golang",
		Price:   100,
		Website: "https://golang.org",
		Tags:    []string{"golang", "programming", "learn"},
	}

	c2 := Course{
		Title:   "Python",
		Price:   200,
		Website: "https://python.org",
		Tags:    []string{"python", "programming", "learn"},
	}

	// JSON Marshalling
	xc := []Course{c1, c2}
	// bs := marshal.MarshalDemo(xc)
	bs := marshal.MarshalIndentDemo(xc)
	fmt.Println("Marshaled:")
	fmt.Println(string(bs))

	fmt.Println("-------------------------------------")

	// JSON Unmarshalling
	var courses []Course
	unmarshal.UnmarshalDemo(bs, &courses)
	fmt.Println(courses[0])
	fmt.Println(courses[1])

	fmt.Println("-------------------------------------")

	// JSON Encoding
	// encode.EncodeDemo(xc)
	encode.EncodeIndentDemo(xc, os.Stdout)

	fmt.Println("-------------------------------------")

	// JSON Decoding
	var coursesNew []Course
	json := `[{"Title": "Golang", "Price": 100, "Website": "https://golang.org", "Tags": ["golang", "programming", "learn"]} ,{"Title": "Python", "Price": 200, "Website": "https://python.org", "Tags": ["python", "programming", "learn"]}]`
	decode.DecodeDemo(&coursesNew, strings.NewReader(json))

	fmt.Println(coursesNew[0])
	fmt.Println(coursesNew[1])

	// A better way to demonstrate JSON Encoding and Decoding is to build a server that reads and writes JSON - http ResponseWriter (io.Writer) and *Request (io.Reader).
}

// JSON		-> String	:= Marshal
// String	-> JSON		:= Unmarshal
// JSON		-> Stream := Encode
// Stream -> JSON 	:= Decode

// String = []byte

// Encoder and decoder write struct to slice of a stream or read data from a slice of a stream and convert it into a struct. Internally, they implement the marshal/unmarshal method.

// The Encoder therefore, uses more code and memory overhead than the simpler json.Marshal.

// The difference is in use case - if you want to play with string or bytes use marshal and unmarshal, but if any data you want to read or write to some writer interface, use encode and decode.
