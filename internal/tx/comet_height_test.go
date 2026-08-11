package tx

import (
	"encoding/json"
	"math"
	"strconv"
	"testing"
)

func TestCometHeightAcceptsQuotedAndNumericInt64(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		wire string
		want int64
	}{
		{name: "quoted", wire: `"42"`, want: 42},
		{name: "numeric", wire: `42`, want: 42},
		{name: "quoted negative", wire: `"-1"`, want: -1},
		{name: "numeric negative", wire: `-1`, want: -1},
		{name: "maximum", wire: strconv.FormatInt(math.MaxInt64, 10), want: math.MaxInt64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got CometHeight
			if err := json.Unmarshal([]byte(tc.wire), &got); err != nil {
				t.Fatalf("Unmarshal(%s): %v", tc.wire, err)
			}
			if int64(got) != tc.want {
				t.Fatalf("Unmarshal(%s) = %d, want %d", tc.wire, got, tc.want)
			}
		})
	}
}

func TestCometHeightRejectsNonIntegerAndMalformedValues(t *testing.T) {
	t.Parallel()

	for _, wire := range []string{
		`null`,
		`true`,
		`1.5`,
		`1e3`,
		`""`,
		`"not-a-number"`,
		`9223372036854775808`,
		`"9223372036854775808"`,
		`+1`,
		`01`,
	} {
		wire := wire
		t.Run(wire, func(t *testing.T) {
			t.Parallel()
			var got CometHeight
			if err := json.Unmarshal([]byte(wire), &got); err == nil {
				t.Fatalf("Unmarshal(%s) unexpectedly succeeded with %d", wire, got)
			}
		})
	}
}
