// Command report turns benchmark result directories into one self-contained
// HTML report (inline SVG charts, no external resources) and a Markdown
// summary.
//
//	go run ./bench/report [-out DIR] RESULTS_DIR...
//
// Each RESULTS_DIR is recognised by its contents: matrix.csv (bench/run.sh),
// points.csv (bench/scaling.sh), verify.json (bench/accuracy.sh) or a
// machine.env with mode=passive (bench/passive.sh). Output: DIR/report.html
// and DIR/report.md (default DIR: the first RESULTS_DIR).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	out := flag.String("out", "", "output directory (default: the first RESULTS_DIR)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: report [-out DIR] RESULTS_DIR...")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	rep := &Report{Generated: time.Now()}
	for _, dir := range flag.Args() {
		if err := rep.load(dir); err != nil {
			fmt.Fprintln(os.Stderr, "report:", err)
			os.Exit(1)
		}
	}
	if *out == "" {
		*out = flag.Arg(0)
	}
	secs := rep.sections()
	for name, body := range map[string]string{"report.html": renderHTML(secs), "report.md": renderMarkdown(secs)} {
		p := filepath.Join(*out, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "report:", err)
			os.Exit(1)
		}
		fmt.Println(p)
	}
}
