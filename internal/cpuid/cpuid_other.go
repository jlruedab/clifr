//go:build !amd64

package cpuid

func cpuid(eax, ecx uint32) (a, b, c, d uint32, ok bool) { return 0, 0, 0, 0, false }
