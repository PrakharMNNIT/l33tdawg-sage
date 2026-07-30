package main

import "errors"

const vendoredQuorumTransitionMessage = "first-party companion nodes cannot join or enable quorum mode; use federation to connect separate SAGE nodes"

var errVendoredQuorumTransition = errors.New(vendoredQuorumTransitionMessage)

// rejectVendoredQuorumTransition protects the immutable direct-app-v23
// genesis contract. A vendored companion is born on a single-validator
// personal chain; adopting a quorum genesis would discard that provenance and
// make the still-configured companion fail closed on its next startup.
func rejectVendoredQuorumTransition(cfg *Config) error {
	if cfg != nil && cfg.VendoredAgentBootstrap != nil {
		return errVendoredQuorumTransition
	}
	return nil
}

// setNetworkMode persists the live Settings toggle without ever exposing an
// invalid in-memory or on-disk vendored configuration. Generic nodes retain the
// historical toggle behavior.
func setNetworkMode(cfg *Config, enabled bool) error {
	if enabled {
		if err := rejectVendoredQuorumTransition(cfg); err != nil {
			return err
		}
	}
	previous := cfg.Quorum.Enabled
	cfg.Quorum.Enabled = enabled
	if err := SaveConfig(cfg); err != nil {
		cfg.Quorum.Enabled = previous
		return err
	}
	return nil
}
