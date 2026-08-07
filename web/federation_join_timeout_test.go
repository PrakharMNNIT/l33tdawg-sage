package web

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/federation"
)

type joinConfirmDeadlineDriver struct {
	FederationJoinDriver
	hasDeadline bool
	remaining   time.Duration
}

type joinScanDeadlineDriver struct {
	FederationJoinDriver
	hasDeadline bool
	remaining   time.Duration
}

type delayedJoinScanDriver struct {
	FederationJoinDriver
	delay time.Duration
}

func (d *delayedJoinScanDriver) GuestScan(ctx context.Context, _, _ string) (*federation.GuestScanResult, error) {
	select {
	case <-time.After(d.delay):
		return &federation.GuestScanResult{SessionID: "slow-scan-completed"}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *joinScanDeadlineDriver) GuestScan(ctx context.Context, _, _ string) (*federation.GuestScanResult, error) {
	deadline, ok := ctx.Deadline()
	d.hasDeadline = ok
	if ok {
		d.remaining = time.Until(deadline)
	}
	return &federation.GuestScanResult{}, nil
}

func TestFedGuestScanAllowsFiveMinuteDiscoveryWindow(t *testing.T) {
	driver := &joinScanDeadlineDriver{}
	h := NewDashboardHandler(nil, "test")
	h.Federation = driver
	req := httptest.NewRequest(http.MethodPost, "/v1/dashboard/federation/join/guest/scan",
		bytes.NewBufferString(`{"uri":"otpauth://totp/SAGE:test","endpoint":"https://127.0.0.1:18444"}`))
	rr := httptest.NewRecorder()
	h.handleFedGuestScan(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.True(t, driver.hasDeadline)
	require.LessOrEqual(t, driver.remaining, fedJoinDiscoveryTimeout)
	require.Greater(t, driver.remaining, fedJoinDiscoveryTimeout-time.Second,
		"JOIN discovery inherited the ordinary dashboard call deadline")
}

func TestFedGuestScanExtendsOnlyItsOuterServerWriteDeadline(t *testing.T) {
	driver := &delayedJoinScanDriver{delay: 100 * time.Millisecond}
	h := NewDashboardHandler(nil, "test")
	h.Federation = driver
	mux := http.NewServeMux()
	mux.HandleFunc("/scan", h.handleFedGuestScan)
	mux.HandleFunc("/ordinary", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(driver.delay)
		w.WriteHeader(http.StatusNoContent)
	})

	server := httptest.NewUnstartedServer(mux)
	server.Config.WriteTimeout = 25 * time.Millisecond
	server.Start()
	defer server.Close()
	client := server.Client()
	client.Timeout = time.Second

	response, err := client.Post(server.URL+"/scan", "application/json", bytes.NewBufferString(
		`{"uri":"otpauth://totp/SAGE:test","endpoint":"https://127.0.0.1:18444"}`,
	))
	require.NoError(t, err, "the route-local deadline must outlive the outer server's ordinary budget")
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusOK, response.StatusCode, string(body))
	require.Contains(t, string(body), "slow-scan-completed")

	// The same server still applies its short default to every other route. A
	// route-local JOIN exception must not become a server-wide timeout increase.
	ordinary, ordinaryErr := client.Get(server.URL + "/ordinary")
	if ordinaryErr == nil {
		_, ordinaryErr = io.ReadAll(ordinary.Body)
		_ = ordinary.Body.Close()
	}
	require.Error(t, ordinaryErr, "unrelated requests unexpectedly inherited the JOIN deadline")
}

func (d *joinConfirmDeadlineDriver) GuestConfirm(ctx context.Context, _, _ string, _ federation.ScopeWire) (string, error) {
	deadline, ok := ctx.Deadline()
	d.hasDeadline = ok
	if ok {
		d.remaining = time.Until(deadline)
	}
	return "confirm-tx", nil
}

func TestFedGuestConfirmUsesFullJoinOperationDeadline(t *testing.T) {
	// Keep the expected deadline short and distinct from fedCallTimeout without
	// waiting for it. The production helper derives its value from this override.
	t.Setenv("SAGE_TX_COMMIT_TIMEOUT_MS", "1000")
	want := federation.JoinConfirmationOperationTimeout()
	require.Less(t, want, fedCallTimeout)

	driver := &joinConfirmDeadlineDriver{}
	h := NewDashboardHandler(nil, "test")
	h.Federation = driver
	body := bytes.NewBufferString(`{
		"session_id":"session",
		"endpoint":"https://127.0.0.1:18444",
		"host_scope":{"max_clearance":4,"allowed_domains":[],"mode":"exchange","direction":"both"}
	}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/dashboard/federation/join/guest/confirm", body)
	rr := httptest.NewRecorder()
	h.handleFedGuestConfirm(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.True(t, driver.hasDeadline)
	require.LessOrEqual(t, driver.remaining, want)
	require.Greater(t, driver.remaining, want-time.Second,
		"final confirmation inherited the ordinary call deadline instead of the two-commit operation budget")
}
