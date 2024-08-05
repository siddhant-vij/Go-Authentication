package decode

import (
	"encoding/json"
	"io"
)

func DecodeDemo(xc interface{}, r io.Reader) {
	// NewDecoder returns a new decoder that reads from r.
	// Works best with an io.Reader (http request body, file, os.Stdin).
	decoder := json.NewDecoder(r)

	// Decode reads the next JSON-encoded value from its input and stores it in the value pointed to by v.
	err := decoder.Decode(&xc)
	if err != nil {
		panic(err)
	}
}
