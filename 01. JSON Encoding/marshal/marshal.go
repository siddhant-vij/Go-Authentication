package marshal

import (
	"encoding/json"
)

func MarshalDemo(xc interface{}) []byte {
	// Marshal returns the JSON encoding of xc.
	bs, err := json.Marshal(xc)
	if err != nil {
		panic(err)
	}
	return bs
}

func MarshalIndentDemo(xc interface{}) []byte {
	// MarshalIndent is like Marshal, but each JSON object is indented two spaces.
	bs, err := json.MarshalIndent(xc, "", "  ")
	if err != nil {
		panic(err)
	}
	return bs
}
