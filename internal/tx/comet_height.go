package tx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// CometHeight accepts the two integer encodings seen on CometBFT JSON-RPC
// surfaces: a JSON string (the canonical encoding) or a JSON number. It stays
// deliberately narrower than json.Number: fractions, exponents, null, booleans,
// malformed strings, and values outside int64 are rejected.
type CometHeight int64

func (h *CometHeight) UnmarshalJSON(data []byte) error {
	if h == nil {
		return fmt.Errorf("cannot unmarshal Comet height into a nil receiver")
	}

	raw := bytes.TrimSpace(data)
	if len(raw) == 0 {
		return fmt.Errorf("Comet height is empty")
	}

	var decimal string
	if raw[0] == '"' {
		if err := json.Unmarshal(raw, &decimal); err != nil {
			return fmt.Errorf("decode quoted Comet height: %w", err)
		}
	} else {
		if !json.Valid(raw) {
			return fmt.Errorf("Comet height is not valid JSON")
		}
		decimal = string(raw)
	}

	value, err := strconv.ParseInt(decimal, 10, 64)
	if err != nil {
		return fmt.Errorf("decode Comet height %q: %w", decimal, err)
	}
	*h = CometHeight(value)
	return nil
}
