package abci

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/l33tdawg/sage/internal/store"
	"github.com/l33tdawg/sage/internal/tx"
)

func TestAppV23FederationAdminElevationBindsActionAndRejectsReplay(t *testing.T) {
	app := setupTestApp(t)
	root := newAgentKey(t)
	admin := newAgentKey(t)
	registerAppV23Agent(t, app, root, store.AppV23RoleAdmin, 1, 0)
	registerAppV23Agent(t, app, admin, store.AppV23RoleAdmin, 2, 0)
	require.NoError(t, app.badgerStore.EnsureAppV23Root("federation-envelope-scope", 10))
	promoteAppV23TestAdmin(t, app, root, admin, 10)
	app.appV23AppliedHeight = 10

	tests := []struct {
		name    string
		parsed  *tx.ParsedTx
		mutate  func(*tx.ParsedTx)
		restore func(*tx.ParsedTx)
	}{
		{
			name: "tx33",
			parsed: crossFedSetTx(
				t, admin, termsFor("peer-envelope-set", []string{"shared"}),
			),
			mutate: func(parsed *tx.ParsedTx) {
				parsed.CrossFedTerms.AllowedDomains = []string{"broader"}
			},
			restore: func(parsed *tx.ParsedTx) {
				parsed.CrossFedTerms.AllowedDomains = []string{"shared"}
			},
		},
		{
			name:   "tx34",
			parsed: crossFedRevokeTx(t, admin, "peer-envelope-revoke", "original"),
			mutate: func(parsed *tx.ParsedTx) {
				parsed.CrossFedRevoke.Reason = "substituted"
			},
			restore: func(parsed *tx.ParsedTx) {
				parsed.CrossFedRevoke.Reason = "original"
			},
		},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nonce := "federation_envelope_" + tc.name
			attachAppV23Elevation(
				t, tc.parsed, root, admin, "federation-envelope-scope",
				nonce, 11+int64(i),
			)
			tc.mutate(tc.parsed)
			require.Error(t, app.enforceAppV23ControlElevation(tc.parsed, 11+int64(i)),
				"Root proof must reject action substitution")

			tc.restore(tc.parsed)
			require.NoError(t, app.enforceAppV23ControlElevation(tc.parsed, 11+int64(i)),
				"invalid substitution must not consume the valid one-action nonce")
			require.Error(t, app.enforceAppV23ControlElevation(tc.parsed, 11+int64(i)),
				"accepted federation elevation must reject replay")
		})
	}
}
