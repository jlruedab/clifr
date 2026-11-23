package cpuid

func cpuidAsm(eax, ecx uint32) (a, b, c, d uint32)

func cpuid(eax, ecx uint32) (a, b, c, d uint32, ok bool) {
	a, b, c, d = cpuidAsm(eax, ecx)
	return a, b, c, d, true
}
