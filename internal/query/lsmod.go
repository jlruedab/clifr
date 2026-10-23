package query

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// Module is one loaded kernel module of /proc/modules.
type Module struct {
	Name    string   `json:"name"`
	Size    int64    `json:"size"`
	UseCnt  int      `json:"used"` // -2: no reference count (as lsmod prints it)
	UsedBy  []string `json:"used_by"`
	State   string   `json:"state"` // Live, Loading, Unloading
	Taints  string   `json:"taints,omitempty"`
	Address string   `json:"-"`
}

// ModulesAt returns the modules loaded at t, in /proc/modules' order (the
// newest first). UsedBy is in the order lsmod lists /sys/module/*/holders:
// sysfs lists a directory in kernfs order (kernfsHash).
func ModulesAt(db *store.DB, t int64) ([]Module, error) {
	lines, _, ok, err := FileAt(db, "modules", t)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("lsmod: modules not recorded at %s (recorded since schema 9)", FormatMS(t))
	}
	var out []Module
	for _, l := range lines {
		// name size refcnt holders state address [taints]
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		m := Module{Name: f[0], UseCnt: -2, State: f[4]}
		m.Size, _ = strconv.ParseInt(f[1], 10, 64)
		if n, err := strconv.Atoi(f[2]); err == nil {
			m.UseCnt = n
		}
		if len(f) > 5 {
			m.Address = f[5]
		}
		if len(f) > 6 {
			m.Taints = strings.Trim(f[6], "()")
		}
		for _, h := range strings.Split(f[3], ",") {
			if h != "" && h != "-" && h != "[permanent]" {
				m.UsedBy = append(m.UsedBy, h)
			}
		}
		sort.SliceStable(m.UsedBy, func(i, j int) bool {
			hi, hj := kernfsHash(m.UsedBy[i]), kernfsHash(m.UsedBy[j])
			if hi != hj {
				return hi < hj
			}
			return m.UsedBy[i] < m.UsedBy[j]
		})
		out = append(out, m)
	}
	return out, nil
}

// PrintLsmod prints the modules as kmod's lsmod.
func PrintLsmod(w io.Writer, mods []Module) {
	fmt.Fprintln(w, "Module                  Size  Used by")
	for _, m := range mods {
		line := fmt.Sprintf("%-19s %8d  %d", m.Name, m.Size, m.UseCnt)
		if len(m.UsedBy) > 0 {
			line += " " + strings.Join(m.UsedBy, ",")
		}
		fmt.Fprintln(w, line)
	}
}
