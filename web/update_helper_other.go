//go:build !darwin

package web

func markPendingUpdateStartup(string) error { return nil }

func platformStartPendingUpdateRecovery(string) (func(), func(), error) {
	return func() {}, func() {}, nil
}
