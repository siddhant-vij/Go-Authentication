package unmarshal

import (
	"encoding/json"
)

func UnmarshalDemo(bs []byte, xc interface{}) {
	// Unmarshal parses the JSON-encoded data and stores the result in the value pointed to by xc.
	err := json.Unmarshal(bs, &xc)
	if err != nil {
		panic(err)
	}
}
