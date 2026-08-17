//go:build windows

package mcp

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

type claimantFileLease struct {
	file       *os.File
	overlapped windows.Overlapped
}

func tryLockClaimantFile(path string) (*claimantFileLease, bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600) //nolint:gosec // private path under SAGE_HOME
	if err != nil {
		return nil, false, fmt.Errorf("open claimant identity lock: %w", err)
	}
	lease := &claimantFileLease{file: f}
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lease.overlapped)
	if err != nil {
		_ = f.Close()
		if err == windows.ERROR_LOCK_VIOLATION {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("lock claimant identity: %w", err)
	}
	return lease, true, nil
}

func (l *claimantFileLease) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &l.overlapped)
	return l.file.Close()
}
