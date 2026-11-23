package recorder

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// aarch32 is lscpu's test for 32-bit support on arm64: personality(PER_LINUX32)
// succeeds (then the previous persona is restored), on a locked OS thread.
func aarch32() bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	const perLinux32 = 0x0008
	old, _, errno := unix.RawSyscall(unix.SYS_PERSONALITY, perLinux32, 0, 0)
	if errno != 0 || int(old) == -1 {
		return false
	}
	unix.RawSyscall(unix.SYS_PERSONALITY, old, 0, 0)
	return true
}
