// lscpu, following util-linux's sys-utils/lscpu*.c (2.37, 2.39, 2.41) and
// lscpu.c (2.32), GPL-2.0-or-later (packaging/notices/util-linux.txt): its
// cpuinfo parsing, topology, caches, summary, -e, -p and -C, from the files
// clifrd records as lscpu reads them (snapshot sources "cpus" and
// "cpuinfo", recorder/cpus.go) and the CPUs' MHz at the sample.

package query

import (
	"fmt"
	"io"
	"math/bits"
	"sort"
	"strconv"
	"strings"

	"clifr/internal/store"
)

// cpuSet is a set of logical CPUs.
type cpuSet map[int]bool

func (s cpuSet) list() []int {
	var out []int
	for c := range s {
		out = append(out, c)
	}
	sort.Ints(out)
	return out
}

func (s cpuSet) overlaps(o cpuSet) bool {
	for c := range s {
		if o[c] {
			return true
		}
	}
	return false
}

// parseCPUList reads a sysfs CPU list ("0-3,5").
func parseCPUList(s string) cpuSet {
	out := cpuSet{}
	for _, part := range strings.Split(strings.TrimSpace(s), ",") {
		if part == "" {
			continue
		}
		a, b, rng := strings.Cut(part, "-")
		lo, err := strconv.Atoi(a)
		if err != nil {
			continue
		}
		hi := lo
		if rng {
			hi, _ = strconv.Atoi(b)
		}
		for c := lo; c <= hi; c++ {
			out[c] = true
		}
	}
	return out
}

// parseCPUMask reads a sysfs CPU mask ("00000000,0000003f").
func parseCPUMask(s string) cpuSet {
	out := cpuSet{}
	words := strings.Split(strings.TrimSpace(s), ",")
	for i := range words {
		w := words[len(words)-1-i]
		v, err := strconv.ParseUint(w, 16, 32)
		if err != nil {
			continue
		}
		for v != 0 {
			b := bits.TrailingZeros64(v)
			out[i*32+b] = true
			v &^= 1 << b
		}
	}
	return out
}

// cpulistCreate is util-linux's cpulist_create: "0-3,5,7-9".
func cpulistCreate(s cpuSet) string {
	l := s.list()
	var parts []string
	for i := 0; i < len(l); {
		j := i
		for j+1 < len(l) && l[j+1] == l[j]+1 {
			j++
		}
		switch {
		case j == i:
			parts = append(parts, strconv.Itoa(l[i]))
		default:
			parts = append(parts, strconv.Itoa(l[i])+"-"+strconv.Itoa(l[j]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}

// cpumaskCreate is util-linux's cpumask_create: the mask in hex from its
// highest nonzero nibble ("3fffff"; "0" for an empty set).
func cpumaskCreate(s cpuSet, maxcpus int) string {
	n := (maxcpus + 3) / 4
	nib := make([]byte, n)
	for i := range nib {
		v := 0
		for b := 0; b < 4; b++ {
			if s[i*4+b] {
				v |= 1 << b
			}
		}
		nib[n-1-i] = "0123456789abcdef"[v]
	}
	out := strings.TrimLeft(string(nib), "0")
	if out == "" {
		return "0"
	}
	return out
}

// lscpuType is a CPU type (lscpu_cputype): what cpuinfo says of it and its
// topology.
type lscpuType struct {
	vendor, model, modelname, family, stepping, revision string
	bogomips, flags, addrsz, mtid                        string
	threadsPerCore, coresPerSocket                       int
	coremaps, socketmaps, bookmaps, drawermaps           []cpuSet
	hasFreq                                              bool
	// 2.32's whole-system counts (nthreads, ncores, nsockets...).
}

// lscpuCPU is a logical CPU.
type lscpuCPU struct {
	id                         int
	typ                        *lscpuType
	coreID, socketID           int
	bookID, drawerID           int
	maxMHz, minMHz, curMHz     float64
	bogomips                   string
	hasTopology                bool
	threadSib, coreSib, bookSb cpuSet
	drawerSib                  cpuSet
}

// lscpuCache is a cache (lscpu_cache): name, type, level, id and size, and
// the CPUs sharing it.
type lscpuCache struct {
	name, typ                 string
	level, id                 int
	size                      uint64
	ways, phyLine, sets, line uint32
	allocPol, writePol        string
	shared                    cpuSet
}

// Lscpu is what lscpu reads, as recorded at a moment.
type Lscpu struct {
	TS                  int64 `json:"ts_ms"`
	arch                string
	bit32, bit64        bool
	maxcpus             int
	cpus                []*lscpuCPU // the possible CPUs, by logical id
	present, online     cpuSet
	types               []*lscpuType
	caches              []lscpuCache
	nodes               []int
	nodemaps            []cpuSet
	vulns               [][2]string
	virtVendor, virtTyp string
	virtFlag            string
	freqBoost           int  // -1 unknown
	cluster             bool // arm64 without ACPI PPTT, one CPU type
	mhz                 map[int]float64
	// for 2.32
	cpuinfoMHz string
	rawCaches  []lscpuCache // per index of the first CPU (2.32)
}

// LscpuAt reads the recording at t into lscpu's model.
func LscpuAt(db *store.DB, t int64) (*Lscpu, error) {
	sys, ts, ok, err := FileAt(db, "cpus", t)
	if err != nil {
		return nil, err
	}
	info, _, ok2, err := FileAt(db, "cpuinfo", t)
	if err != nil {
		return nil, err
	}
	if !ok || !ok2 {
		return nil, fmt.Errorf("lscpu: the CPUs are recorded since 2026-11-23 (not at %s)", FormatMS(t))
	}
	arch := MetaAt(db, "uname_machine", t)
	if arch == "" {
		arch = db.Meta("uname_machine")
	}
	// The MHz now: cpu_samples' (cpuinfo's, as scaling_cur_freq usually is).
	mhz := map[int]float64{}
	if rows, err := db.Query(`SELECT cpu, mhz FROM cpu_samples WHERE ts = (SELECT MAX(ts) FROM cpu_samples WHERE ts <= ?)
		AND cpu >= 0 AND mhz IS NOT NULL AND mhz >= 0`, t); err == nil {
		for rows.Next() {
			var c int
			var m int64
			if rows.Scan(&c, &m) == nil {
				mhz[c] = float64(m) / 100
			}
		}
		rows.Close()
	}
	x := newLscpu(arch, sys, info, mhz)
	x.TS = ts
	return x, nil
}

// newLscpu builds lscpu's model from the recorded lines ("cpus": path, tab,
// content; "cpuinfo") and each CPU's MHz.
func newLscpu(arch string, sys, info []string, mhz map[int]float64) *Lscpu {
	x := &Lscpu{freqBoost: -1, mhz: mhz, arch: arch}
	f := map[string]string{}
	var keys []string
	for _, l := range sys {
		k, v, _ := strings.Cut(l, "\t")
		f[k] = strings.ReplaceAll(v, "\\n", "\n")
		keys = append(keys, k)
	}
	x.maxcpus = 2048
	if n, err := strconv.Atoi(f["kernel_max"]); err == nil {
		x.maxcpus = n + 1
	}
	possible := parseCPUList(f["possible"])
	x.present, x.online = parseCPUList(f["present"]), parseCPUList(f["online"])
	if _, ok := f["present"]; !ok {
		x.present = nil
	}
	if _, ok := f["online"]; !ok {
		x.online = nil
	}
	for _, c := range possible.list() {
		x.cpus = append(x.cpus, &lscpuCPU{id: c, coreID: -1, socketID: -1, bookID: -1, drawerID: -1})
	}
	byID := map[int]*lscpuCPU{}
	for _, c := range x.cpus {
		byID[c.id] = c
	}
	x.parseCPUInfo(info, byID)
	x.archBits()
	if x.arch == "aarch64" {
		x.bit32 = f["aarch32"] == "true"
		x.cluster = f["pptt"] == "false" && len(x.types) == 1
		for _, t := range x.types {
			armDecode(t)
		}
	}
	// Vulnerabilities, sorted by name.
	for _, k := range keys {
		if name, ok := strings.CutPrefix(k, "vulnerabilities/"); ok && f[k] != "" {
			n := strings.ToUpper(name[:1]) + strings.ReplaceAll(name[1:], "_", " ")
			text := f[k]
			if rest, ok := strings.CutPrefix(text, "Mitigation"); ok && rest != "" {
				// The character after "Mitigation" becomes ';', every ':' goes.
				text = strings.ReplaceAll("Mitigation;"+rest[1:], ":", "")
			}
			x.vulns = append(x.vulns, [2]string{n, text})
		}
	}
	sort.SliceStable(x.vulns, func(i, j int) bool { return x.vulns[i][0] < x.vulns[j][0] })
	// NUMA nodes.
	for _, k := range keys {
		if rest, ok := strings.CutPrefix(k, "node/node"); ok {
			if n, err := strconv.Atoi(strings.TrimSuffix(rest, "/cpumap")); err == nil {
				x.nodes = append(x.nodes, n)
			}
		}
	}
	sort.Ints(x.nodes)
	for _, n := range x.nodes {
		x.nodemaps = append(x.nodemaps, parseCPUMask(f["node/node"+strconv.Itoa(n)+"/cpumap"]))
	}
	if v, ok := f["cpufreq/boost"]; ok {
		x.freqBoost, _ = strconv.Atoi(v)
	}
	if v, ok := f["virt"]; ok {
		x.virtVendor, x.virtTyp, _ = strings.Cut(v, "\t")
	}
	if len(x.types) > 0 {
		fl := " " + x.types[0].flags + " "
		switch {
		case strings.Contains(fl, " svm "):
			x.virtFlag = "svm"
		case strings.Contains(fl, " vmx "):
			x.virtFlag = "vmx"
		}
	}
	x.readTopology(f)
	return x
}

// parseCPUInfo is lscpu_read_cpuinfo for the fields of x86 and aarch64: a
// type field already set in the current type starts a new type; a
// "processor" line gives the CPU before it the current type; types are
// then deduplicated by vendor, model, model name and stepping.
func (x *Lscpu) parseCPUInfo(lines []string, byID map[int]*lscpuCPU) {
	var cur *lscpuCPU
	var typ *lscpuType
	var types []*lscpuType
	field := func(t *lscpuType, name string) *string {
		switch name {
		case "BogoMIPS":
			return &t.bogomips
		case "CPU implementer", "vendor", "vendor_id":
			return &t.vendor
		case "CPU part", "model":
			return &t.model
		case "CPU revision", "revision":
			return &t.revision
		case "CPU variant", "stepping":
			return &t.stepping
		case "Features", "flags":
			return &t.flags
		case "address sizes":
			return &t.addrsz
		case "cpu family", "family":
			return &t.family
		case "model name":
			return &t.modelname
		case "max thread id":
			return &t.mtid
		}
		return nil
	}
	for _, l := range lines {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if v == "" {
			continue
		}
		switch k {
		case "processor":
			if cur != nil && typ != nil {
				cur.typ = typ
			}
			id, _ := strconv.Atoi(v)
			cur = byID[id]
			continue
		case "bogomips":
			if cur != nil {
				cur.bogomips = v
			}
			if typ != nil && typ.bogomips == "" {
				typ.bogomips = v
			}
			continue
		case "cpu MHz":
			x.cpuinfoMHz = v
			continue
		}
		if typ != nil {
			if p := field(typ, k); p != nil && *p != "" {
				typ = nil // don't overwrite the current type: a new one
			}
		}
		probe := &lscpuType{}
		if field(probe, k) == nil {
			continue
		}
		if typ == nil {
			typ = &lscpuType{}
			types = append(types, typ)
		}
		*field(typ, k) = v
	}
	if cur != nil && cur.typ == nil {
		cur.typ = typ
	}
	// deduplicate_cputypes
	key := func(t *lscpuType) [4]string { return [4]string{t.vendor, t.model, t.modelname, t.stepping} }
	sort.SliceStable(types, func(i, j int) bool {
		a, b := key(types[i]), key(types[j])
		for k := range a {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return false
	})
	repl := map[*lscpuType]*lscpuType{}
	var uniq []*lscpuType
	for _, t := range types {
		if len(uniq) > 0 && key(uniq[len(uniq)-1]) == key(t) {
			repl[t] = uniq[len(uniq)-1]
			continue
		}
		uniq = append(uniq, t)
	}
	if len(uniq) == 2 { // the first only a subset of the second (ppc): one type
		a, b := uniq[0], uniq[1]
		sub := true
		for _, p := range [][2]string{{a.model, b.model}, {a.modelname, b.modelname}, {a.vendor, b.vendor},
			{a.bogomips, b.bogomips}, {a.revision, b.revision}} {
			if p[0] != "" && p[0] != p[1] {
				sub = false
			}
		}
		if sub {
			repl[a] = b
			uniq = uniq[1:]
		}
	}
	x.types = uniq
	for _, c := range x.cpus {
		if r, ok := repl[c.typ]; ok {
			c.typ = r
		}
		if c.typ == nil && len(uniq) > 0 {
			c.typ = uniq[0]
		}
	}
}

// archBits is lscpu_read_architecture's op-modes: x86 32-bit always, 64-bit
// with lm; aarch64 64-bit, 32-bit when clifrd found PER_LINUX32 works (not
// recorded yet: assumed).
func (x *Lscpu) archBits() {
	switch x.arch {
	case "x86_64", "i386", "i686":
		x.bit32 = true
	case "aarch64":
		x.bit64 = true
	}
	if len(x.types) > 0 && strings.Contains(" "+x.types[0].flags+" ", " lm ") {
		x.bit32, x.bit64 = true, true
	}
}

// readTopology is cputype_read_topology, read_ids, read_mhz and read_caches.
func (x *Lscpu) readTopology(f map[string]string) {
	onlineState := -1
	if v, ok := f["hotplug/states"]; ok {
		n, _, _ := strings.Cut(v, ":")
		onlineState, _ = strconv.Atoi(strings.TrimSpace(n))
	}
	add := func(ary []cpuSet, s cpuSet) []cpuSet {
		for _, a := range ary {
			if a.overlaps(s) {
				return ary
			}
		}
		return append(ary, s)
	}
	for _, t := range x.types {
		nthreads := 0
		for _, c := range x.cpus {
			if c.typ != t {
				continue
			}
			p := "cpu" + strconv.Itoa(c.id) + "/"
			ts, ok := f[p+"topology/thread_siblings"]
			if !ok {
				continue
			}
			if st, err := strconv.Atoi(f[p+"hotplug/state"]); err == nil && onlineState > 0 && st != onlineState {
				continue
			}
			c.hasTopology = true
			c.threadSib = parseCPUMask(ts)
			n := len(c.threadSib)
			if n == 0 {
				n = 1
			}
			nthreads = max(nthreads, n)
			t.coremaps = add(t.coremaps, c.threadSib)
			if v, ok := f[p+"topology/core_siblings"]; ok {
				c.coreSib = parseCPUMask(v)
				t.socketmaps = add(t.socketmaps, c.coreSib)
			}
			if v, ok := f[p+"topology/book_siblings"]; ok {
				t.bookmaps = add(t.bookmaps, parseCPUMask(v))
			}
			if v, ok := f[p+"topology/drawer_siblings"]; ok {
				t.drawermaps = add(t.drawermaps, parseCPUMask(v))
			}
		}
		t.threadsPerCore = nthreads
		if t.mtid != "" {
			if n, err := strconv.Atoi(t.mtid); err == nil {
				t.threadsPerCore = n + 1
			}
		}
		if len(t.socketmaps) > 0 {
			t.coresPerSocket = len(t.coremaps) / len(t.socketmaps)
		}
	}
	for _, c := range x.cpus {
		if c.typ == nil {
			continue
		}
		p := "cpu" + strconv.Itoa(c.id) + "/"
		id := func(k string) int {
			if n, err := strconv.Atoi(f[p+"topology/"+k]); err == nil {
				return n
			}
			return -1
		}
		if _, ok := f[p+"topology/core_id"]; ok || c.hasTopology {
			c.coreID, c.socketID, c.bookID, c.drawerID = id("core_id"), id("physical_package_id"), id("book_id"), id("drawer_id")
		}
		if v, err := strconv.Atoi(f[p+"cpufreq/cpuinfo_max_freq"]); err == nil {
			c.maxMHz = float64(float32(v) / 1000)
		}
		if v, err := strconv.Atoi(f[p+"cpufreq/cpuinfo_min_freq"]); err == nil {
			c.minMHz = float64(float32(v) / 1000)
		}
		c.curMHz = x.mhz[c.id]
		if c.minMHz != 0 || c.maxMHz != 0 {
			c.typ.hasFreq = true
		}
		// caches
		for i := 0; ; i++ {
			q := p + "cache/index" + strconv.Itoa(i) + "/"
			lv, err := strconv.Atoi(f[q+"level"])
			if err != nil {
				if _, ok := f[q+"type"]; !ok {
					break
				}
				continue
			}
			typ := f[q+"type"]
			if typ == "" {
				continue
			}
			cid := -1
			if v, err := strconv.Atoi(f[q+"id"]); err == nil {
				cid = v
			}
			if cid == -1 { // mk_cache_id
				idx := 0
				for _, ca := range x.caches {
					if ca.level != lv || ca.typ != typ {
						continue
					}
					if ca.shared[c.id] {
						break
					}
					idx++
				}
				cid = idx
			}
			k := -1
			for j, ca := range x.caches {
				if ca.id == cid && ca.level == lv && ca.typ == typ {
					k = j
				}
			}
			if k < 0 {
				name := "L" + strconv.Itoa(lv)
				switch typ {
				case "Data":
					name += "d"
				case "Instruction":
					name += "i"
				}
				u := func(n string) uint32 { v, _ := strconv.ParseUint(f[q+n], 10, 32); return uint32(v) }
				ca := lscpuCache{name: name, typ: typ, level: lv, id: cid, ways: u("ways_of_associativity"),
					phyLine: u("physical_line_partition"), sets: u("number_of_sets"), line: u("coherency_line_size"),
					allocPol: f[q+"allocation_policy"], writePol: f[q+"write_policy"], size: parseSizeK(f[q+"size"])}
				x.caches = append(x.caches, ca)
				k = len(x.caches) - 1
				if c == x.cpus[0] {
					x.rawCaches = append(x.rawCaches, ca)
				}
			}
			if x.caches[k].shared == nil {
				x.caches[k].shared = parseCPUMask(f[q+"shared_cpu_map"])
			}
		}
	}
	sort.SliceStable(x.caches, func(i, j int) bool { return x.caches[i].name < x.caches[j].name })
}

// parseSizeK is parse_size for sysfs cache sizes ("48K", "2048K").
func parseSizeK(s string) uint64 {
	s = strings.TrimSpace(s)
	mult := uint64(1)
	switch {
	case strings.HasSuffix(s, "K"):
		mult, s = 1024, strings.TrimSuffix(s, "K")
	case strings.HasSuffix(s, "M"):
		mult, s = 1024*1024, strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "G"):
		mult, s = 1024*1024*1024, strings.TrimSuffix(s, "G")
	}
	n, _ := strconv.ParseUint(s, 10, 64)
	return n * mult
}

// cacheFullSize is lscpu_get_cache_full_size: the size of every instance.
func (x *Lscpu) cacheFullSize(name string) (uint64, int) {
	var sz uint64
	n := 0
	for _, ca := range x.caches {
		if ca.name == name {
			sz += ca.size
			n++
		}
	}
	return sz, n
}

// LscpuOpts are lscpu's options.
type LscpuOpts struct {
	Mode       string // "" summary, "e" extended, "p" parsable, "C" caches
	Cols       []string
	ColsAdd    bool
	Hex, Bytes bool
	Physical   bool // -y
	Online     bool // -b
	Offline    bool // -c
	All        bool // -a
	OutputAll  bool
	Hierarchic bool   // --hierarchic=always
	Version    string // ToolStyle.Lscpu: "" 2.41, "2.39", "2.37", "2.32"
}

// sizeHuman3 is size_to_human_string with SIZE_SUFFIX_3LETTER|SPACE
// ("544 KiB", "18 MiB").
func sizeHuman3(n uint64) string {
	s := utilHuman(int64(n))
	if len(s) == 0 {
		return s
	}
	unit := s[len(s)-1]
	if unit == 'B' {
		return s[:len(s)-1] + " B"
	}
	return s[:len(s)-1] + " " + string(unit) + "iB"
}

// PrintLscpu prints the summary or the table o asks for.
func PrintLscpu(w io.Writer, x *Lscpu, o LscpuOpts) error {
	switch o.Mode {
	case "e":
		return x.printReadable(w, o)
	case "p":
		return x.printParsable(w, o)
	case "C":
		return x.printCaches(w, o)
	}
	if o.Version == "2.32" {
		x.printSummary232(w, o)
		return nil
	}
	x.printSummary(w, o)
	return nil
}

// summary rows: a field and its value, printed as libsmartcols' two
// columns without headings (the field column as wide as the longest).
type sumRows [][2]string

func (r *sumRows) add(k, v string) { *r = append(*r, [2]string{k, v}) }

func (r sumRows) print(w io.Writer) {
	wd := 0
	for _, x := range r {
		wd = max(wd, len(x[0]))
	}
	for _, x := range r {
		fmt.Fprintf(w, "%-*s %s\n", wd, x[0], x[1])
	}
}

func (x *Lscpu) cpusetText(s cpuSet, hex bool) string {
	if hex {
		return cpumaskCreate(s, x.maxcpus)
	}
	return cpulistCreate(s)
}

func (x *Lscpu) printSummary(w io.Writer, o LscpuOpts) { x.summary(o).print(w) }

func (x *Lscpu) summary(o LscpuOpts) sumRows {
	var r sumRows
	r.add("Architecture:", x.arch)
	if x.bit32 || x.bit64 {
		p := "64-bit"
		switch {
		case x.bit32 && x.bit64:
			p = "32-bit, 64-bit"
		case x.bit32:
			p = "32-bit"
		}
		r.add("CPU op-mode(s):", p)
	}
	if len(x.types) > 0 && x.types[0].addrsz != "" {
		r.add("Address sizes:", x.types[0].addrsz)
	}
	r.add("Byte Order:", "Little Endian")
	r.add("CPU(s):", strconv.Itoa(len(x.present)))
	if x.online != nil {
		k := "On-line CPU(s) list:"
		if o.Hex {
			k = "On-line CPU(s) mask:"
		}
		r.add(k, x.cpusetText(x.online, o.Hex))
		if len(x.online) != len(x.present) {
			off := cpuSet{}
			for _, c := range x.cpus {
				if x.present[c.id] && !x.online[c.id] {
					off[c.id] = true
				}
			}
			k = "Off-line CPU(s) list:"
			if o.Hex {
				k = "Off-line CPU(s) mask:"
			}
			r.add(k, x.cpusetText(off, o.Hex))
		}
	}
	if len(x.types) > 0 && x.types[0].vendor != "" {
		r.add("Vendor ID:", x.types[0].vendor)
	}
	for _, t := range x.types {
		switch {
		case t.modelname != "":
			r.add("Model name:", t.modelname)
		case o.Version != "2.37":
			r.add("Model name:", "-")
		}
		if t.family != "" {
			r.add("CPU family:", t.family)
		}
		if t.model != "" || t.revision != "" {
			v := t.model
			if t.revision != "" {
				v = t.revision
			}
			r.add("Model:", v)
		}
		r.add("Thread(s) per core:", strconv.Itoa(t.threadsPerCore))
		if x.cluster {
			r.add("Core(s) per cluster:", strconv.Itoa(t.coresPerSocket))
		} else {
			r.add("Core(s) per socket:", strconv.Itoa(t.coresPerSocket))
		}
		if x.cluster && len(t.bookmaps) == 0 {
			// The number of sockets comes from DMI, root's only: "-".
			r.add("Socket(s):", "-")
			r.add("Cluster(s):", strconv.Itoa(len(t.socketmaps)))
		} else if len(t.bookmaps) > 0 {
			r.add("Socket(s) per book:", strconv.Itoa(len(t.socketmaps)/len(t.bookmaps)))
			if len(t.drawermaps) > 0 {
				r.add("Book(s) per drawer:", strconv.Itoa(len(t.bookmaps)/len(t.drawermaps)))
				r.add("Drawer(s):", strconv.Itoa(len(t.drawermaps)))
			} else {
				r.add("Book(s):", strconv.Itoa(len(t.bookmaps)))
			}
		} else {
			r.add("Socket(s):", strconv.Itoa(len(t.socketmaps)))
		}
		if t.stepping != "" {
			r.add("Stepping:", t.stepping)
		}
		if x.freqBoost >= 0 {
			r.add("Frequency boost:", map[bool]string{true: "enabled", false: "disabled"}[x.freqBoost != 0])
		}
		if t.hasFreq {
			if o.Version != "2.37" {
				var fmax, fcur float32
				for _, c := range x.cpus {
					if c.typ != t || !x.present[c.id] || c.maxMHz <= 0 || c.curMHz <= 0 {
						continue
					}
					fmax += float32(c.maxMHz)
					fcur += float32(c.curMHz)
				}
				if fcur > 0 {
					r.add("CPU(s) scaling MHz:", fmt.Sprintf("%.0f%%", fcur/fmax*100))
				}
			}
			maxm, minm := float32(0), float32(-1)
			for _, c := range x.cpus {
				if c.typ != t || !x.present[c.id] {
					continue
				}
				maxm = max(maxm, float32(c.maxMHz))
				if c.minMHz != 0 && (minm < 0 || float32(c.minMHz) < minm) {
					minm = float32(c.minMHz)
				}
			}
			r.add("CPU max MHz:", fmt.Sprintf("%.4f", maxm))
			r.add("CPU min MHz:", fmt.Sprintf("%.4f", minm))
		}
		if t.bogomips != "" {
			if o.Version == "2.37" {
				r.add("BogoMIPS:", t.bogomips)
			} else {
				v, _ := strconv.ParseFloat(t.bogomips, 32)
				r.add("BogoMIPS:", fmt.Sprintf("%.2f", float32(v)))
			}
		}
		if t.flags != "" {
			r.add("Flags:", t.flags)
		}
	}
	switch x.virtFlag {
	case "svm":
		r.add("Virtualization:", "AMD-V")
	case "vmx":
		r.add("Virtualization:", "VT-x")
	}
	if x.virtVendor != "" {
		r.add("Hypervisor vendor:", x.virtVendor)
		r.add("Virtualization type:", x.virtTyp)
	}
	last := ""
	for _, ca := range x.caches {
		if ca.name == last {
			continue
		}
		last = ca.name
		sz, n := x.cacheFullSize(ca.name)
		if sz == 0 {
			continue
		}
		inst := "instances"
		if n == 1 {
			inst = "instance"
		}
		v := fmt.Sprintf("%s (%d %s)", sizeHuman3(sz), n, inst)
		if o.Bytes {
			v = fmt.Sprintf("%d (%d %s)", sz, n, inst)
		}
		r.add(ca.name+" cache:", v)
	}
	if len(x.nodes) > 0 {
		r.add("NUMA node(s):", strconv.Itoa(len(x.nodes)))
		for i, n := range x.nodes {
			r.add(fmt.Sprintf("NUMA node%d CPU(s):", n), x.cpusetText(x.nodemaps[i], o.Hex))
		}
	}
	for _, v := range x.vulns {
		r.add("Vulnerability "+v[0]+":", v[1])
	}
	return r
}

// printSummary232 is util-linux 2.32's print_summary.
func (x *Lscpu) printSummary232(w io.Writer, o LscpuOpts) { x.summary232(o).print(w) }

func (x *Lscpu) summary232(o LscpuOpts) sumRows {
	var r sumRows
	r.add("Architecture:", x.arch)
	if x.bit32 || x.bit64 {
		var m []string
		if x.bit32 {
			m = append(m, "32-bit")
		}
		if x.bit64 {
			m = append(m, "64-bit")
		}
		r.add("CPU op-mode(s):", strings.Join(m, ", "))
	}
	r.add("Byte Order:", "Little Endian")
	r.add("CPU(s):", strconv.Itoa(len(x.present)))
	if x.online != nil {
		k := "On-line CPU(s) list:"
		if o.Hex {
			k = "On-line CPU(s) mask:"
		}
		r.add(k, x.cpusetText(x.online, o.Hex))
	}
	var t *lscpuType
	if len(x.types) > 0 {
		t = x.types[0]
	}
	if t != nil && len(t.socketmaps) > 0 {
		threads, cores := 0, len(t.coremaps)
		for _, c := range t.coremaps {
			threads += len(c)
		}
		if cores > 0 {
			r.add("Thread(s) per core:", strconv.Itoa(threads/cores))
			r.add("Core(s) per socket:", strconv.Itoa(cores/len(t.socketmaps)))
		}
		r.add("Socket(s):", strconv.Itoa(len(t.socketmaps)))
	}
	if len(x.nodes) > 0 {
		r.add("NUMA node(s):", strconv.Itoa(len(x.nodes)))
	}
	if t != nil {
		if t.vendor != "" {
			r.add("Vendor ID:", t.vendor)
		}
		if t.family != "" {
			r.add("CPU family:", t.family)
		}
		if t.model != "" || t.revision != "" {
			v := t.model
			if t.revision != "" {
				v = t.revision
			}
			r.add("Model:", v)
		}
		if t.modelname != "" {
			r.add("Model name:", t.modelname)
		}
		if t.stepping != "" {
			r.add("Stepping:", t.stepping)
		}
		if m, ok := x.mhz[x.cpus[len(x.cpus)-1].id]; ok && m > 0 {
			r.add("CPU MHz:", fmt.Sprintf("%.3f", m))
		}
		maxm, minm := 0.0, 0.0
		for _, c := range x.cpus {
			maxm = max(maxm, c.maxMHz)
			if c.minMHz > 0 && (minm == 0 || c.minMHz < minm) {
				minm = c.minMHz
			}
		}
		if maxm > 0 {
			r.add("CPU max MHz:", fmt.Sprintf("%.4f", maxm))
		}
		if minm > 0 {
			r.add("CPU min MHz:", fmt.Sprintf("%.4f", minm))
		}
		if t.bogomips != "" {
			r.add("BogoMIPS:", t.bogomips)
		}
	}
	switch x.virtFlag {
	case "svm":
		r.add("Virtualization:", "AMD-V")
	case "vmx":
		r.add("Virtualization:", "VT-x")
	}
	if x.virtVendor != "" {
		r.add("Hypervisor vendor:", x.virtVendor)
		r.add("Virtualization type:", x.virtTyp)
	}
	// The first CPU's caches by name, each one's size as sysfs gives it.
	raw := append([]lscpuCache(nil), x.rawCaches...)
	sort.SliceStable(raw, func(i, j int) bool { return raw[i].name < raw[j].name })
	for _, ca := range raw {
		r.add(ca.name+" cache:", fmt.Sprintf("%dK", ca.size/1024))
	}
	for i, n := range x.nodes {
		r.add(fmt.Sprintf("NUMA node%d CPU(s):", n), x.cpusetText(x.nodemaps[i], o.Hex))
	}
	if t != nil && t.flags != "" {
		r.add("Flags:", t.flags)
	}
	return r
}

// lscpuCPUCols: -e/-p's columns: name, right-aligned, abbreviation.
var lscpuCPUCols = []struct {
	name        string
	right, abbr bool
}{{"BOGOMIPS", true, true}, {"CPU", true, true}, {"CORE", true, false}, {"SOCKET", true, false},
	{"CLUSTER", true, false}, {"NODE", true, false}, {"BOOK", true, false}, {"DRAWER", true, false},
	{"CACHE", false, false}, {"POLARIZATION", false, false}, {"ADDRESS", false, false},
	{"CONFIGURED", false, false}, {"ONLINE", true, false}, {"MHZ", true, false}, {"SCALMHZ%", true, false},
	{"MAXMHZ", true, false}, {"MINMHZ", true, false}, {"MODELNAME", false, false}}

// lscpuColsSince: -e/-p columns a release does not have yet.
var lscpuColsSince = map[string]map[string]bool{
	"2.32": {"BOGOMIPS": true, "CLUSTER": true, "MHZ": true, "SCALMHZ%": true, "MODELNAME": true},
	"2.37": {"SCALMHZ%": true, "MODELNAME": true},
}

// LscpuColumnIn reports whether a release ("" 2.41) has -e/-p column name.
func LscpuColumnIn(name, version string) bool {
	return LscpuColumn(name, false) && !lscpuColsSince[version][name]
}

// LscpuColumn reports whether name is one of -e/-p's (cache false) or -C's
// columns.
func LscpuColumn(name string, cache bool) bool {
	if cache {
		for _, c := range lscpuCacheCols {
			if c.name == name {
				return true
			}
		}
		return false
	}
	for _, c := range lscpuCPUCols {
		if c.name == name {
			return true
		}
	}
	return false
}

func (x *Lscpu) cacheNames() []string {
	var out []string
	last := ""
	for _, ca := range x.caches {
		if ca.name != last {
			out = append(out, ca.name)
			last = ca.name
		}
	}
	return out
}

// fillID is __fill_id: the index of the map the CPU is in, or its physical
// id with -y.
func fillID(phys bool, cpu int, id int, maps []cpuSet) string {
	if phys {
		if id < 0 {
			return "-"
		}
		return strconv.Itoa(id)
	}
	for i, m := range maps {
		if m[cpu] {
			return strconv.Itoa(i)
		}
	}
	return ""
}

func (x *Lscpu) cell(c *lscpuCPU, col string, o LscpuOpts, compat bool) string {
	if c.typ == nil {
		return ""
	}
	switch col {
	case "CPU":
		return strconv.Itoa(c.id)
	case "BOGOMIPS":
		b := c.bogomips
		if b == "" {
			b = c.typ.bogomips
		}
		if b == "" {
			return ""
		}
		v, _ := strconv.ParseFloat(b, 32)
		return fmt.Sprintf("%.2f", float32(v))
	case "CORE":
		return fillID(o.Physical, c.id, c.coreID, c.typ.coremaps)
	case "SOCKET":
		return fillID(o.Physical, c.id, c.socketID, c.typ.socketmaps)
	case "CLUSTER":
		if x.cluster {
			return fillID(o.Physical, c.id, c.socketID, c.typ.socketmaps)
		}
	case "BOOK":
		return fillID(o.Physical, c.id, c.bookID, c.typ.bookmaps)
	case "DRAWER":
		return fillID(o.Physical, c.id, c.drawerID, c.typ.drawermaps)
	case "NODE":
		for i, m := range x.nodemaps {
			if m[c.id] {
				return strconv.Itoa(x.nodes[i])
			}
		}
	case "CACHE":
		sep := ":"
		if compat {
			sep = ","
		}
		var parts []string
		for _, name := range x.cacheNames() {
			for _, ca := range x.caches {
				if ca.name == name && ca.shared[c.id] {
					parts = append(parts, strconv.Itoa(ca.id))
					break
				}
			}
		}
		return strings.Join(parts, sep)
	case "ONLINE":
		if x.online == nil {
			return ""
		}
		if o.Mode == "p" {
			return map[bool]string{true: "Y", false: "N"}[x.online[c.id]]
		}
		return map[bool]string{true: "yes", false: "no"}[x.online[c.id]]
	case "MHZ":
		if c.curMHz != 0 {
			return fmt.Sprintf("%.4f", float32(c.curMHz))
		}
	case "SCALMHZ%":
		if c.curMHz != 0 && c.maxMHz != 0 {
			return fmt.Sprintf("%.0f%%", float32(c.curMHz)/float32(c.maxMHz)*100)
		}
	case "MAXMHZ":
		if c.maxMHz != 0 {
			return fmt.Sprintf("%.4f", float32(c.maxMHz))
		}
	case "MINMHZ":
		if c.minMHz != 0 {
			return fmt.Sprintf("%.4f", float32(c.minMHz))
		}
	case "MODELNAME":
		return c.typ.modelname
	}
	return ""
}

func (x *Lscpu) header(col string, compat bool) string {
	if col == "CACHE" && len(x.caches) > 0 {
		sep := ":"
		if compat {
			sep = ","
		}
		return strings.Join(x.cacheNames(), sep)
	}
	return col
}

// shownCPUs: the CPUs -e and -p list (-a, -b, -c; present ones only).
func (x *Lscpu) shownCPUs(o LscpuOpts) []*lscpuCPU {
	on, off := o.Online || o.All, o.Offline || o.All
	if !on && !off {
		on, off = true, o.Mode == "e"
	}
	var out []*lscpuCPU
	for _, c := range x.cpus {
		if x.online != nil {
			if !off && !x.online[c.id] || !on && x.online[c.id] {
				continue
			}
		}
		if x.present != nil && !x.present[c.id] {
			continue
		}
		out = append(out, c)
	}
	return out
}

func (x *Lscpu) cpuCols(o LscpuOpts) []string {
	var cols []string
	if o.OutputAll {
		for _, c := range lscpuCPUCols {
			if !lscpuColsSince[o.Version][c.name] {
				cols = append(cols, c.name)
			}
		}
	} else if o.Mode == "e" {
		cols = []string{"CPU"}
		var t *lscpuType
		if len(x.types) > 0 {
			t = x.types[0]
		}
		if len(x.nodes) > 0 {
			cols = append(cols, "NODE")
		}
		if t != nil && len(t.drawermaps) > 0 {
			cols = append(cols, "DRAWER")
		}
		if t != nil && len(t.bookmaps) > 0 {
			cols = append(cols, "BOOK")
		}
		if t != nil && len(t.socketmaps) > 0 {
			if x.cluster {
				cols = append(cols, "CLUSTER")
			} else {
				cols = append(cols, "SOCKET")
			}
		}
		if t != nil && len(t.coremaps) > 0 {
			cols = append(cols, "CORE")
		}
		if len(x.caches) > 0 {
			cols = append(cols, "CACHE")
		}
		if x.online != nil {
			cols = append(cols, "ONLINE")
		}
		if t != nil && t.hasFreq {
			cols = append(cols, "MAXMHZ", "MINMHZ")
			if o.Version != "2.32" {
				cols = append(cols, "MHZ")
			}
		}
	} else {
		cols = []string{"CPU", "CORE", "SOCKET", "NODE", "CACHE"}
		if x.cluster {
			cols[2] = "CLUSTER"
		}
	}
	if len(o.Cols) > 0 {
		if o.ColsAdd {
			cols = append(cols, o.Cols...)
		} else {
			cols = append([]string(nil), o.Cols...)
		}
	}
	return cols
}

func (x *Lscpu) printReadable(w io.Writer, o LscpuOpts) error {
	cols := x.cpuCols(o)
	rows := [][]string{make([]string, len(cols))}
	for i, c := range cols {
		rows[0][i] = x.header(c, false)
	}
	for _, c := range x.shownCPUs(o) {
		r := make([]string, len(cols))
		for i, col := range cols {
			r[i] = x.cell(c, col, o, false)
			if r[i] == "" {
				r[i] = "-"
			}
		}
		rows = append(rows, r)
	}
	right := func(i int) bool {
		if o.Version == "2.32" { // its columns are all left-aligned
			return false
		}
		for _, c := range lscpuCPUCols {
			if c.name == cols[i] {
				return c.right
			}
		}
		return false
	}
	printScols(w, rows, right, false)
	return nil
}

func (x *Lscpu) printParsable(w io.Writer, o LscpuOpts) error {
	// The compatible format (",," before the caches): without a column list,
	// and in 2.37 always.
	compat := len(o.Cols) == 0 || o.Version == "2.37"
	cols := x.cpuCols(o)
	from := "starting usually from zero."
	if o.Version == "2.32" {
		from = "starting from zero."
	}
	io.WriteString(w, "# The following is the parsable format, which can be fed to other\n"+
		"# programs. Each different item in every column has an unique ID\n"+
		"# "+from+"\n")
	var b strings.Builder
	b.WriteString("# ")
	for i, col := range cols {
		if col == "CACHE" {
			if compat && len(x.caches) == 0 {
				continue
			}
			if compat && i != 0 {
				b.WriteByte(',')
			}
		}
		if i > 0 {
			b.WriteByte(',')
		}
		h := x.header(col, compat)
		abbr := false
		for _, c := range lscpuCPUCols {
			if c.name == col {
				abbr = c.abbr
			}
		}
		if h != "" && col != "CACHE" && !abbr {
			h = h[:1] + strings.ToLower(h[1:])
		}
		b.WriteString(h)
	}
	fmt.Fprintln(w, b.String())
	for _, c := range x.shownCPUs(o) {
		b.Reset()
		for i, col := range cols {
			if compat && col == "CACHE" {
				if len(x.caches) == 0 {
					continue
				}
				if i > 0 {
					b.WriteByte(',')
				}
			}
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(x.cell(c, col, o, compat))
		}
		fmt.Fprintln(w, b.String())
	}
	return nil
}

var lscpuCacheCols = []struct {
	name  string
	right bool
}{{"ALL-SIZE", true}, {"LEVEL", true}, {"NAME", false}, {"ONE-SIZE", true}, {"TYPE", false}, {"WAYS", true},
	{"ALLOC-POLICY", false}, {"WRITE-POLICY", false}, {"PHY-LINE", true}, {"SETS", true}, {"COHERENCY-SIZE", true}}

func (x *Lscpu) printCaches(w io.Writer, o LscpuOpts) error {
	rows := x.cacheRows(o)
	cols := rows[0]
	right := func(i int) bool {
		for _, c := range lscpuCacheCols {
			if c.name == cols[i] {
				return c.right
			}
		}
		return false
	}
	printScols(w, rows, right, false)
	return nil
}

// cacheRows: -C's header and one row per cache name.
func (x *Lscpu) cacheRows(o LscpuOpts) [][]string {
	cols := []string{"NAME", "ONE-SIZE", "ALL-SIZE", "WAYS", "TYPE", "LEVEL", "SETS", "PHY-LINE", "COHERENCY-SIZE"}
	if o.OutputAll {
		cols = nil
		for _, c := range lscpuCacheCols {
			cols = append(cols, c.name)
		}
	}
	if len(o.Cols) > 0 {
		if o.ColsAdd {
			cols = append(cols, o.Cols...)
		} else {
			cols = append([]string(nil), o.Cols...)
		}
	}
	size := func(n uint64) string {
		if o.Bytes {
			return strconv.FormatUint(n, 10)
		}
		return utilHuman(int64(n))
	}
	rows := [][]string{cols}
	last := ""
	for _, ca := range x.caches {
		if ca.name == last {
			continue
		}
		last = ca.name
		r := make([]string, len(cols))
		for i, c := range cols {
			u := func(v uint32) string {
				if v == 0 {
					return ""
				}
				return strconv.FormatUint(uint64(v), 10)
			}
			switch c {
			case "NAME":
				r[i] = ca.name
			case "ONE-SIZE":
				if ca.size != 0 {
					r[i] = size(ca.size)
				}
			case "ALL-SIZE":
				if sz, _ := x.cacheFullSize(ca.name); sz != 0 {
					r[i] = size(sz)
				}
			case "WAYS":
				r[i] = u(ca.ways)
			case "TYPE":
				r[i] = ca.typ
			case "LEVEL":
				if ca.level != 0 {
					r[i] = strconv.Itoa(ca.level)
				}
			case "ALLOC-POLICY":
				r[i] = ca.allocPol
			case "WRITE-POLICY":
				r[i] = ca.writePol
			case "PHY-LINE":
				r[i] = u(ca.phyLine)
			case "SETS":
				r[i] = u(ca.sets)
			case "COHERENCY-SIZE":
				r[i] = u(ca.line)
			}
		}
		rows = append(rows, r)
	}
	return rows
}

// LscpuJSON is --json: the summary's fields ({"field", "data"}, as lscpu
// -J names them), or each CPU's or cache's row by column name (lower case).
func LscpuJSON(x *Lscpu, o LscpuOpts) []map[string]string {
	var out []map[string]string
	switch o.Mode {
	case "":
		r := x.summary(o)
		if o.Version == "2.32" {
			r = x.summary232(o)
		}
		for _, f := range r {
			out = append(out, map[string]string{"field": f[0], "data": f[1]})
		}
	case "e", "p":
		cols := x.cpuCols(o)
		for _, c := range x.shownCPUs(o) {
			m := map[string]string{}
			for _, col := range cols {
				if v := x.cell(c, col, o, false); v != "" {
					if col == "CACHE" {
						m[strings.ToLower(x.header(col, false))] = v
					} else {
						m[strings.ToLower(col)] = v
					}
				}
			}
			out = append(out, m)
		}
	case "C":
		rows := x.cacheRows(LscpuOpts{Bytes: true, OutputAll: true})
		for _, r := range rows[1:] {
			m := map[string]string{}
			for i, h := range rows[0] {
				if r[i] != "" {
					m[strings.ToLower(h)] = r[i]
				}
			}
			out = append(out, m)
		}
	}
	return out
}

// armDecode is lscpu-arm.c's arm_ids_decode and arm_rXpY_decode: the
// implementer and part ids named, ARM's stepping as rXpY.
func armDecode(t *lscpuType) {
	id := func(s string) int {
		if !strings.HasPrefix(s, "0x") {
			return -1
		}
		n, err := strconv.ParseInt(s[2:], 16, 32)
		if err != nil {
			return -1
		}
		return int(n)
	}
	impl := id(t.vendor)
	if impl <= 0 {
		return
	}
	if im, ok := armImplementers[impl]; ok {
		t.vendor = im.name
		if part := id(t.model); part > 0 {
			if name, ok := im.parts[part]; ok {
				t.modelname = name
			}
		}
	}
	if impl == 0x41 && t.revision != "" && t.stepping != "" {
		rev, err1 := strconv.Atoi(t.revision)
		vr, err2 := strconv.ParseInt(t.stepping, 0, 32)
		if err1 == nil && err2 == nil {
			t.stepping = fmt.Sprintf("r%dp%d", vr, rev)
		}
	}
}
