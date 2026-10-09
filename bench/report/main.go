// Command report turns benchmark result directories into one self-contained
// HTML report (inline SVG charts, no external resources) and a Markdown
// summary.
//
//	go run ./bench/report [-out DIR] [-validate] [-allow-invalid] RESULTS_DIR...
//
// Each RESULTS_DIR is recognised by its contents: matrix.csv (bench/run.sh),
// points.csv (bench/scaling.sh), verify.json (bench/accuracy.sh) or a
// machine.env with mode=passive (bench/passive.sh). Output: DIR/report.html
// and DIR/report.md (default DIR: the first RESULTS_DIR).
//
// Missing or implausible metrics (see validate.go) are listed on stderr and
// make it exit with status 1 without writing anything, unless -allow-invalid,
// which writes the report with the problems at the top. -validate only checks
// (the bench scripts run it after every run).
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
	check := flag.Bool("validate", false, "only check the data; exit 1 if anything is missing or implausible")
	allow := flag.Bool("allow-invalid", false, "write the report even if validation fails, listing the problems")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: report [-out DIR] [-validate] [-allow-invalid] RESULTS_DIR...")
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
	problems := rep.validate()
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "report: INVALID:", p)
	}
	if len(problems) > 0 && !*allow {
		fmt.Fprintf(os.Stderr, "report: %d problem(s); fix the data or pass -allow-invalid\n", len(problems))
		os.Exit(1)
	}
	if *check {
		return
	}
	if *out == "" {
		*out = flag.Arg(0)
	}
	secs := rep.sections()
	if len(problems) > 0 {
		v := section{Title: "Validation problems", Level: 2}
		v.Blocks = append(v.Blocks, block{Para: fmt.Sprintf("%d metric(s) are missing or implausible; the figures that depend on them are not trustworthy.", len(problems))})
		for _, p := range problems {
			v.Blocks = append(v.Blocks, block{Para: p})
		}
		secs = append([]section{v}, secs...)
	}
	for name, body := range map[string]string{"report.html": renderHTML(secs), "report.md": renderMarkdown(secs)} {
		p := filepath.Join(*out, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "report:", err)
			os.Exit(1)
		}
		fmt.Println(p)
	}
}
