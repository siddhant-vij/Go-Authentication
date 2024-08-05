package encode

import (
	"encoding/json"
	"io"
)

func EncodeDemo(xc interface{}, w io.Writer) {
	// NewEncoder returns a new encoder that writes to w.
	// Works best with an io.Writer (http response body, file, os.Stdout).
	encoder := json.NewEncoder(w)

	// Encode writes the JSON encoding of xc to the stream.
	err := encoder.Encode(xc)
	if err != nil {
		panic(err)
	}
}

func EncodeIndentDemo(xc interface{}, w io.Writer) {
	// NewEncoder returns a new encoder that writes to w.
	encoder := json.NewEncoder(w)

	// SetIndent instructs the encoder to format each subsequent encoded value
	encoder.SetIndent("", "  ")

	// Encode writes the JSON encoding of xc to the stream.
	err := encoder.Encode(xc)
	if err != nil {
		panic(err)
	}
}
