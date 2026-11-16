package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"clifr/internal/pqstore"
)

// sealSetupCmd is `clifrd seal-setup [--new]`: starts sealing the
// recording's integrity log (docs/sealing.md). The verification key is
// printed once, on standard output, and never stored on this host.
func sealSetupCmd(args []string) error {
	fs := flag.NewFlagSet("clifrd seal-setup", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "clifrd seal-setup starts sealing the recording's integrity log: from the next flush, each\n"+
			"flush is sealed with a key that changes every time, the previous key overwritten. Someone who\n"+
			"later gains root here cannot alter what was sealed before without clifr verify --integrity\n"+
			"--seal-key KEY saying so (only the last flush interval is not protected yet).\n\n"+
			"The verification key is printed once, on standard output, and is not stored on this host:\n"+
			"keep it elsewhere (a password manager, the analysis host). Whoever holds it can also forge\n"+
			"seals, so keep it like a password. clifrd need not be restarted.\n\n"+
			"Usage:\n  clifrd seal-setup [--new] [--data-dir DIR]\n\nOptions:\n")
		fs.PrintDefaults()
	}
	dataDir := defaultDataDir
	if d := os.Getenv("CLIFR_DATA_DIR"); d != "" {
		dataDir = d
	}
	fs.StringVar(&dataDir, "data-dir", dataDir, "Parquet data directory")
	fs.StringVar(&dataDir, "D", dataDir, "short for --data-dir")
	newChain := fs.Bool("new", false, "start a new chain with a new key when sealing was set up before (the key\nwas lost, or seal.state is missing or damaged); the old chain stays verifiable with its own key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("seal-setup: unexpected argument %q", fs.Arg(0))
	}
	if st, err := os.Stat(dataDir); err != nil || !st.IsDir() {
		return fmt.Errorf("seal-setup: no data directory %s", dataDir)
	}
	key, id, err := pqstore.SealSetup(dataDir, *newChain)
	if err != nil {
		return fmt.Errorf("seal-setup: %w", err)
	}
	host, _ := os.Hostname()
	mid, _ := os.ReadFile("/etc/machine-id")
	fmt.Fprintf(os.Stderr, "clifrd: sealing set up for %s\n"+
		"  host %s, machine-id %s, %s\n"+
		"  key id %s; sealing starts at clifrd's next flush\n\n"+
		"The verification key follows. It is shown only now and is not stored here: copy it to\n"+
		"somewhere off this host, then clear this terminal's scrollback.\n\n",
		dataDir, host, strings.TrimSpace(string(mid)), time.Now().Format("2006-01-02 15:04:05 MST"), id)
	fmt.Println(key)
	fmt.Fprintf(os.Stderr, "\nCheck the recording with: clifr verify --integrity --seal-key KEY\n")
	return nil
}
