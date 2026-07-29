package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type recordingFederationVaultLoader struct {
	events     *[]string
	passphrase string
	count      int
}

func (l *recordingFederationVaultLoader) SetVaultPassphrase(passphrase string) int {
	l.passphrase = passphrase
	*l.events = append(*l.events, "federation-seeds")
	return l.count
}

func TestChainFederationVaultUnlockRestoresSeedsBeforeAdmission(t *testing.T) {
	events := []string{}
	loader := &recordingFederationVaultLoader{
		events: &events,
		count:  2,
	}
	reported := -1
	unlock := chainFederationVaultUnlock(
		func(passphrase string) {
			require.Equal(t, "correct horse battery staple", passphrase)
			events = append(events, "local-admission")
		},
		loader,
		func(count int) {
			reported = count
			events = append(events, "seed-report")
		},
	)

	unlock("correct horse battery staple")

	require.Equal(t, "correct horse battery staple", loader.passphrase)
	require.Equal(t, 2, reported)
	require.Equal(t, []string{
		"federation-seeds",
		"seed-report",
		"local-admission",
	}, events)
}
