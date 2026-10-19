package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const defaultConfig = "/etc/clifr/clifrd.yml"

// scalar takes any YAML scalar as its text ("30s", 2G, 72h, 2%).
type scalar string

func (s *scalar) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: want a single value", n.Line)
	}
	*s = scalar(n.Value)
	return nil
}

// fileConfig is clifrd.yml. Each setting is the value of a flag; a flag
// given on the command line wins.
type fileConfig struct {
	DataDir   scalar `yaml:"data_dir"`
	Retention scalar `yaml:"retention"`
	MaxSize   scalar `yaml:"max_size"`
	LogLevel  scalar `yaml:"log_level"`
	Intervals struct {
		Process  scalar `yaml:"process"`
		System   scalar `yaml:"system"`
		Files    scalar `yaml:"files"`
		Keyframe scalar `yaml:"keyframe"`
		Flush    scalar `yaml:"flush"`
	} `yaml:"intervals"`
	Collectors struct {
		ProcessEvents scalar `yaml:"process_events"`
		TCP           scalar `yaml:"tcp"`
		Files         scalar `yaml:"files"`
	} `yaml:"collectors"`
	CPUBudget    scalar `yaml:"cpu_budget"`
	GCHeapTarget scalar `yaml:"gc_heap_target"`
}

// notYet names settings of the clifrd.yml spec that this release rejects.
var notYet = map[string]string{
	"memory_limit": "use gc_heap_target: a hard memory limit makes the garbage collector run continuously (CPU); the systemd unit's MemoryMax is the hard limit",
	"redact":       "command-line redaction is not available yet",
	"encryption":   "encryption is not available in this release",
}

// applyConfig reads the configuration file and sets every flag it gives
// that was not given on the command line. A missing file is an error only
// when it was named with -C/--config.
func applyConfig(fset *flag.FlagSet, path string, named bool) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) && !named {
		return nil
	}
	if err != nil {
		return err
	}
	var top map[string]any
	if err := yaml.Unmarshal(b, &top); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for k := range top {
		if why, ok := notYet[k]; ok {
			return fmt.Errorf("%s: %s: %s", path, k, why)
		}
	}
	var c fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) { // io.EOF: an empty file
		return fmt.Errorf("%s: %w", path, err)
	}
	if c.Intervals.System != "" && c.Intervals.System != c.Intervals.Process {
		return fmt.Errorf("%s: intervals.system: a system interval apart from intervals.process is not available yet", path)
	}
	given := map[string]bool{}
	fset.Visit(func(f *flag.Flag) { given[f.Name] = true })
	for _, s := range []struct {
		flag string
		v    scalar
	}{
		{"data-dir", c.DataDir}, {"retention", c.Retention}, {"max-size", c.MaxSize}, {"log-level", c.LogLevel},
		{"interval", c.Intervals.Process}, {"fd-interval", c.Intervals.Files},
		{"keyframe-interval", c.Intervals.Keyframe}, {"flush-interval", c.Intervals.Flush},
		{"events", c.Collectors.ProcessEvents}, {"tcp", c.Collectors.TCP}, {"fd-mode", c.Collectors.Files},
		{"cpu-budget", c.CPUBudget}, {"gc-heap-target", c.GCHeapTarget},
	} {
		if s.v == "" || given[s.flag] || given[short[s.flag]] {
			continue
		}
		if err := fset.Set(s.flag, string(s.v)); err != nil {
			return fmt.Errorf("%s: %s: %w", path, yamlName(s.flag), err)
		}
	}
	return nil
}

// short maps a flag to its one-letter alias.
var short = map[string]string{"data-dir": "D", "config": "C"}

func yamlName(flagName string) string {
	for y, f := range map[string]string{"intervals.process": "interval", "intervals.files": "fd-interval",
		"intervals.keyframe": "keyframe-interval", "intervals.flush": "flush-interval",
		"collectors.process_events": "events", "collectors.tcp": "tcp", "collectors.files": "fd-mode"} {
		if f == flagName {
			return y
		}
	}
	return strings.ReplaceAll(flagName, "-", "_")
}
