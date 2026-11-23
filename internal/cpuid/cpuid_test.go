package cpuid

import "testing"

// TestHypervisorSignature: it runs; inside a VM it names the hypervisor.
func TestHypervisorSignature(t *testing.T) {
	t.Logf("hypervisor signature %q", HypervisorSignature())
}
