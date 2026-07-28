package idfmt

import "testing"

func TestPrefixIsPanicFreeAndPreservesCanonicalDisplay(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
	}{
		{name: "empty", id: "", want: ""},
		{name: "legacy short", id: "short", want: "short"},
		{name: "exact width", id: "0123456789abcdef", want: "0123456789abcdef"},
		{name: "canonical", id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", want: "0123456789abcdef"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Prefix(tt.id); got != tt.want {
				t.Fatalf("Prefix(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}
