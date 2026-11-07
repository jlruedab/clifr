package remote

import "syscall"

// syscallNoFollow makes opening a data file fail if it was swapped for a
// symlink after the Lstat check.
const syscallNoFollow = syscall.O_NOFOLLOW
