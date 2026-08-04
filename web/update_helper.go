package web

// MarkPendingUpdateStartup records that the replacement process entered its
// own executable. The external macOS recovery helper uses this as the strict
// boundary after which it must never launch an older binary automatically.
func MarkPendingUpdateStartup(execPath string) error {
	return markPendingUpdateStartup(execPath)
}

func startPendingUpdateRecovery(execPath string) (commit, abort func(), err error) {
	return platformStartPendingUpdateRecovery(execPath)
}
