// Command benchtool holds the small data tools used by the benchmark
// scripts:
//
//	benchtool pglat PGBENCH_OUT LOG...   TPS and latency percentiles from pgbench logs
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: benchtool pglat|... args")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "pglat":
		err = pglat(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "benchtool:", err)
		os.Exit(1)
	}
}
