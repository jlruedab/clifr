package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"time"
)

// startProfile writes the recorder's own profiles to dir (--pprof-dir): one
// CPU profile over the whole run (cpu.pprof), a heap profile every 30 s
// (heap-<seconds since start>.pprof) and the Go memory statistics at the same
// moments (memstats.csv). The returned function ends the CPU profile.
func startProfile(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	cpu, err := os.Create(filepath.Join(dir, "cpu.pprof"))
	if err != nil {
		return nil, err
	}
	if err := pprof.StartCPUProfile(cpu); err != nil {
		return nil, err
	}
	ms, err := os.Create(filepath.Join(dir, "memstats.csv"))
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(ms, "seconds,heap_alloc,heap_inuse,heap_idle,heap_released,stack_inuse,sys,next_gc,num_gc,gc_cpu_fraction,goroutines")
	start := time.Now()
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
			}
			sec := int(time.Since(start).Seconds())
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			fmt.Fprintf(ms, "%d,%d,%d,%d,%d,%d,%d,%d,%d,%.5f,%d\n", sec, m.HeapAlloc, m.HeapInuse, m.HeapIdle,
				m.HeapReleased, m.StackInuse, m.Sys, m.NextGC, m.NumGC, m.GCCPUFraction, runtime.NumGoroutine())
			if f, err := os.Create(filepath.Join(dir, fmt.Sprintf("heap-%04d.pprof", sec))); err == nil {
				pprof.Lookup("heap").WriteTo(f, 0)
				f.Close()
			}
		}
	}()
	return func() {
		close(done)
		pprof.StopCPUProfile()
		cpu.Close()
		ms.Close()
	}, nil
}
