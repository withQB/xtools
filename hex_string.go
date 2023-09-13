package xtools

import (
	"encoding/hex"
	"encoding/json"
)

// A HexString is a string of bytes that are hex encoded when used in JSON.
// The bytes encoded using hex when marshalled as JSON.
// When the bytes are unmarshalled from JSON they are decoded from hex.
type HexString []byte

// MarshalJSON encodes the bytes as hex and then encodes the hex as a JSON string.
// This takes a value receiver so that maps and slices of HexString encode correctly.
func (h HexString) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h))
}

// UnmarshalJSON decodes a JSON string and then decodes the resulting hex.
// This takes a pointer receiver because it needs to write the result of decoding.
func (h *HexString) UnmarshalJSON(raw []byte) (err error) {
	var str string
	if err = json.Unmarshal(raw, &str); err != nil {
		return
	}

	*h, err = hex.DecodeString(str)
	return
}
