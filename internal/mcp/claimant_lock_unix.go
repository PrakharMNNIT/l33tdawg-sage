//go:build !windows

package mcp

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type claimantFileLease struct{ file *os.File }

func tryLockClaimantFile(path string) (*claimantFileLease, bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600) //nolint:gosec // private path under SAGE_HOME
	if err != nil {
		return nil, false, fmt.Errorf("open claimant identity lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if err == unix.EWOULDBLOCK || err == unix.EAGAIN {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("lock claimant identity: %w", err)
	}
	return &claimantFileLease{file: f}, true, nil
}

func (l *claimantFileLease) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	return l.file.Close()
}
