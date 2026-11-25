package broker

import (
	"fmt"
	"syscall"
)

const prSetDumpable = 4 // PR_SET_DUMPABLE, from <linux/prctl.h>

// Harden makes the memory of the process harder to reach: no core dump, no
// ptrace or /proc/<pid>/mem from other processes of the same user, and, when
// lock is set, no page ever written to swap.
//
// It does not protect against root, nor against a process running under the
// same user that starts the broker. Run the broker under a user of its own.
func Harden(lock bool) error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return fmt.Errorf("disabling core dumps: %w", err)
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE, 0): %w", errno)
	}
	if lock {
		if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE); err != nil {
			return fmt.Errorf("mlockall: %w (raise RLIMIT_MEMLOCK, e.g. LimitMEMLOCK=infinity in systemd)", err)
		}
	}
	return nil
}
