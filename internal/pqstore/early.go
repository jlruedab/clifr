package pqstore

import (
	"strings"

	"clifr/internal/store"
)

// RequestFlush asks for an early flush at the next sample (EarlyFlush
// still applies). Safe from any goroutine.
func (s *Store) RequestFlush(reason string) {
	s.requested.Store(&reason)
}

// earlyKernel are kernel messages at error level that often come shortly
// before a hang or a crash; any message at crit, alert or emerg level
// (soft lockups, panics, fatal machine checks) counts too.
var earlyKernel = []string{
	"blocked for more than", // hung task
	"I/O error",             // block layer, buffer I/O
	"-fs error",             // EXT4-fs error, ...
	"Corruption of in-memory data", "Hardware Error", "watchdog:", "rcu_sched self-detected stall", "rcu: INFO:",
}

// earlyReason says why b should be flushed early, or "".
func (s *Store) earlyReason(b *store.Batch) string {
	if len(b.OOMEvents) > 0 {
		return "OOM kill"
	}
	for i := range b.Kmsg {
		k := &b.Kmsg[i]
		if k.Kind != "msg" || k.MonoUS < s.openMonoUS { // older ones are the buffer read again at start
			continue
		}
		level := k.Prio & 7
		hit := level <= 2
		for _, p := range earlyKernel {
			if hit || level > 4 {
				break
			}
			hit = strings.Contains(k.Msg, p)
		}
		if hit {
			m := k.Msg
			if len(m) > 100 {
				m = m[:100] + "..."
			}
			return "kernel message: " + m
		}
	}
	return ""
}
