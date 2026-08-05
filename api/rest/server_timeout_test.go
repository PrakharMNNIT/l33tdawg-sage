package rest

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHTTPServerWriteTimeoutTracksEmbeddingBudget(t *testing.T) {
	for _, tc := range []struct {
		name      string
		canonical string
		alias     string
		want      time.Duration
	}{
		{name: "default", want: 45 * time.Second},
		{name: "canonical 60 seconds", canonical: "60s", want: 75 * time.Second},
		{name: "canonical two minutes", canonical: "2m", want: 135 * time.Second},
		{name: "legacy alias", alias: "60s", want: 75 * time.Second},
		{name: "canonical wins", canonical: "2m", alias: "1ms", want: 135 * time.Second},
		{name: "invalid canonical uses safe default", canonical: "invalid", alias: "1ms", want: 45 * time.Second},
		{name: "bounded", canonical: "24h", want: maxRESTWriteTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SAGE_EMBEDDING_TIMEOUT", tc.canonical)
			t.Setenv("SAGE_EMBED_TIMEOUT", tc.alias)
			server := &Server{}

			plain := server.newHTTPServer("127.0.0.1:0", nil)
			secure := server.newHTTPServer("127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12})

			assert.Equal(t, tc.want, plain.WriteTimeout)
			assert.Equal(t, tc.want, secure.WriteTimeout)
			assert.Equal(t, 15*time.Second, plain.ReadTimeout)
			assert.Equal(t, 60*time.Second, plain.IdleTimeout)
		})
	}
}
