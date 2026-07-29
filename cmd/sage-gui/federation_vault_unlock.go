package main

// federationVaultPassphraseLoader is the narrow post-unlock surface needed by
// node startup. Keeping it as an interface makes the safety ordering directly
// testable without constructing a live federation listener.
type federationVaultPassphraseLoader interface {
	SetVaultPassphrase(string) int
}

// chainFederationVaultUnlock restores encrypted federation TOTP seeds before
// opening the node's ordinary post-unlock admission path. A node that booted
// with its vault locked must not remain "federation locked" until restart.
func chainFederationVaultUnlock(
	next func(string),
	loader federationVaultPassphraseLoader,
	restored func(int),
) func(string) {
	return func(passphrase string) {
		count := loader.SetVaultPassphrase(passphrase)
		if restored != nil {
			restored(count)
		}
		if next != nil {
			next(passphrase)
		}
	}
}
