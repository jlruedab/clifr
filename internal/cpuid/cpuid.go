// Package cpuid reads the hypervisor's signature as lscpu does (CPUID leaf
// 0x40000000), in pure Go and assembly (no cgo).
package cpuid

// HypervisorSignature is the 12 bytes CPUID leaf 0x40000000 returns in EBX,
// ECX and EDX ("KVMKVMKVM\0\0\0", "XenVMMXenVMM"...), up to the first NUL;
// "" where there is no CPUID instruction (not amd64).
func HypervisorSignature() string {
	_, b, c, d, ok := cpuid(0x40000000, 0)
	if !ok {
		return ""
	}
	var s [12]byte
	for i, r := range []uint32{b, c, d} {
		for j := 0; j < 4; j++ {
			s[i*4+j] = byte(r >> (8 * j))
		}
	}
	for i, x := range s {
		if x == 0 {
			return string(s[:i])
		}
	}
	return string(s[:])
}
