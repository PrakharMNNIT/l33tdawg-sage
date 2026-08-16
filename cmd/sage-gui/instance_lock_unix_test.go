//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestInstanceLockExcludesSecondServeAndReleasesCleanly(t *testing.T) {
	t.Setenv(instanceLockFDEnv, "")
	home := t.TempDir()
	first, err := acquireInstanceLock(home)
	require.NoError(t, err)

	// A separately launched process does not inherit our descriptor env.
	require.NoError(t, os.Unsetenv(instanceLockFDEnv))
	second, err := acquireInstanceLock(home)
	require.Error(t, err)
	require.ErrorIs(t, err, errInstanceLockHeld)
	require.Nil(t, second)

	require.NoError(t, first.Close())
	require.NoError(t, os.Unsetenv(instanceLockFDEnv))
	third, err := acquireInstanceLock(home)
	require.NoError(t, err)
	require.NoError(t, third.Close())
}

func TestInstanceLockInheritedHandoffAndForgedFD(t *testing.T) {
	t.Run("valid inherited descriptor", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv(instanceLockFDEnv, "")
		first, err := acquireInstanceLock(home)
		require.NoError(t, err)
		defer first.Close()
		dupFD, err := unix.Dup(int(first.file.Fd()))
		require.NoError(t, err)
		t.Setenv(instanceLockFDEnv, strconv.Itoa(dupFD))
		inherited, err := acquireInstanceLock(home)
		require.NoError(t, err)
		require.NoError(t, inherited.Close())
	})

	t.Run("forged descriptor for another file", func(t *testing.T) {
		home := t.TempDir()
		other, err := os.OpenFile(filepath.Join(t.TempDir(), "other.lock"), os.O_CREATE|os.O_RDWR, 0600)
		require.NoError(t, err)
		t.Setenv(instanceLockFDEnv, strconv.FormatUint(uint64(other.Fd()), 10))
		lock, err := acquireInstanceLock(home)
		require.Error(t, err)
		require.Nil(t, lock)

		// Rejecting a forged descriptor must not create an os.File wrapper whose
		// finalizer can later close the caller-owned descriptor after FD reuse.
		runtime.GC()
		runtime.GC()
		_, err = unix.FcntlInt(other.Fd(), unix.F_GETFD, 0)
		require.NoError(t, err)
		require.NoError(t, other.Close())
	})
}
