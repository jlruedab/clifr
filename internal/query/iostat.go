// iostat's reports and options (-c -d -x -s -k -m -z -N -t), following
// sysstat's iostat.c (12.7.7, 12.5.2, 11.7.3; GPL-2.0-or-later;
// packaging/notices/sysstat.txt): its headers, formats and which devices it
// lists.

package query

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// IOStatOpts are iostat's display options.
type IOStatOpts struct {
	Extended bool // -x
	CPU      bool // the avg-cpu block (default, -c)
	Disk     bool // the device table (default, -d)
	MB       bool // -m: megabytes instead of kilobytes
	Short    bool // -s
	Zero     bool // -z: leave out devices without I/O in the interval
	DevMap   bool // -N: device-mapper names
	Times    bool // -t: the time before each report
}

// PrintIOStat formats reports like sysstat iostat: the avg-cpu block unless
// devOnly, then the basic or the extended (-x) device table.
func PrintIOStat(w io.Writer, reps []IOStatReport, extended, devOnly bool) {
	PrintIOStatOpts(w, reps, IOStatOpts{Extended: extended, CPU: !devOnly, Disk: true})
}

// PrintIOStatOpts prints iostat's first line and each report as write_stats
// does: [-t time] [avg-cpu block] [device table], a blank line after each
// (two in sysstat 12: rw_io_stat_loop adds one).
func PrintIOStatOpts(w io.Writer, reps []IOStatReport, o IOStatOpts) {
	if len(reps) > 0 && reps[0].first != "" {
		fmt.Fprintf(w, "%s\n\n", reps[0].first)
	}
	for _, rep := range reps {
		if o.Times {
			fmt.Fprintln(w, time.UnixMilli(rep.TS).Format("01/02/06 15:04:05"))
		}
		if o.CPU {
			c := rep.CPU
			io.WriteString(w, "avg-cpu:  %user   %nice %system %iowait  %steal   %idle\n")
			fmt.Fprintf(w, "        %7.2f %7.2f %7.2f %7.2f %7.2f %7.2f\n\n", c.User, c.Nice, c.System, c.IOWait, c.Steal, c.Idle)
		}
		if o.Disk {
			if rep.v11 {
				printIOStat11(w, rep, o)
			} else {
				printIOStat12(w, rep, o)
			}
		}
		fmt.Fprintln(w)
		if !rep.v11 { // sysstat 12's loop prints another newline after each report
			fmt.Fprintln(w)
		}
	}
}

// shown: the devices a report lists (-z: those with I/O in the interval) and
// the name printed (-N: a device-mapper device's name).
func (rep IOStatReport) shown(o IOStatOpts) []IOStatDev {
	var out []IOStatDev
	for _, d := range rep.Devices {
		if o.Zero && d.RS+d.WS+d.DS+d.FS == 0 {
			continue
		}
		if o.DevMap && d.DMName != "" {
			d.Device = d.DMName
		}
		out = append(out, d)
	}
	return out
}

// unit is the size unit of the headers and the factor from kB.
func (o IOStatOpts) unit() (string, float64) {
	if o.MB {
		return "MB", 1024
	}
	return "kB", 1
}

// shortVals are -s's merged columns: reads, writes and discards (sysstat
// 11: reads and writes) together.
func shortVals(d IOStatDev, discards bool) (tps, kbs, rqm, await, areq float64) {
	ios := d.RS + d.WS
	tps, kbs, rqm = ios, d.RKBS+d.WKBS, d.RRQMS+d.WRQMS
	ticks := d.RAwait*d.RS + d.WAwait*d.WS
	if discards {
		ios += d.DS
		tps, kbs, rqm = ios, kbs+d.DKBS, rqm+d.DRQMS
		ticks += d.DAwait * d.DS
	}
	return tps, kbs, rqm, div(ticks, ios), div(kbs, ios)
}

func printIOStat12(w io.Writer, rep IOStatReport, o IOStatOpts) {
	u, f := o.unit()
	devs := rep.shown(o)
	switch {
	case o.Extended && o.Short:
		fmt.Fprintf(w, "Device             tps      %s/s    rqm/s   await  areq-sz  aqu-sz  %%util\n", u)
		for _, d := range devs {
			tps, kbs, rqm, await, areq := shortVals(d, true)
			fmt.Fprintf(w, "%-13s %8.2f %9.2f %8.2f %7.2f %8.2f %7.2f %6.2f\n", d.Device, tps, kbs/f, rqm, await, areq, d.AquSz, d.Util)
		}
	case o.Extended:
		fmt.Fprintf(w, "Device            r/s     r%[1]s/s   rrqm/s  %%rrqm r_await rareq-sz     w/s     w%[1]s/s   wrqm/s  %%wrqm w_await wareq-sz     d/s     d%[1]s/s   drqm/s  %%drqm d_await dareq-sz     f/s f_await  aqu-sz  %%util\n", u)
		for _, d := range devs {
			fmt.Fprintf(w, "%-13s %7.2f %9.2f %8.2f %6.2f %7.2f %8.2f %7.2f %9.2f %8.2f %6.2f %7.2f %8.2f %7.2f %9.2f %8.2f %6.2f %7.2f %8.2f %7.2f %7.2f %7.2f %6.2f\n",
				d.Device, d.RS, d.RKBS/f, d.RRQMS, d.RRQMPct, d.RAwait, d.RAreqSz, d.WS, d.WKBS/f, d.WRQMS, d.WRQMPct, d.WAwait, d.WAreqSz,
				d.DS, d.DKBS/f, d.DRQMS, d.DRQMPct, d.DAwait, d.DAreqSz, d.FS, d.FAwait, d.AquSz, d.Util)
		}
	case o.Short:
		fmt.Fprintf(w, "Device             tps    %[1]s_read/s    %[1]s_w+d/s    %[1]s_read    %[1]s_w+d\n", u)
		for _, d := range devs {
			fmt.Fprintf(w, "%-13s %8.2f %12.2f %12.2f %10d %10d\n", d.Device, d.TPS, d.RKBS/f, (d.WKBS+d.DKBS)/f,
				int64(float64(d.KBRead)/f), int64(float64(d.KBWrtn+d.KBDscd)/f))
		}
	default:
		fmt.Fprintf(w, "Device             tps    %[1]s_read/s    %[1]s_wrtn/s    %[1]s_dscd/s    %[1]s_read    %[1]s_wrtn    %[1]s_dscd\n", u)
		for _, d := range devs {
			fmt.Fprintf(w, "%-13s %8.2f %12.2f %12.2f %12.2f %10d %10d %10d\n", d.Device, d.TPS, d.RKBS/f, d.WKBS/f, d.DKBS/f,
				int64(float64(d.KBRead)/f), int64(float64(d.KBWrtn)/f), int64(float64(d.KBDscd)/f))
		}
	}
}

// printIOStat11 prints the devices as sysstat 11 (RHEL 8) does: no discard
// and flush columns, svctm (%util spread over the I/Os, in ms), and sr
// devices named scd as its ioconf maps them; -s only with -x.
func printIOStat11(w io.Writer, rep IOStatReport, o IOStatOpts) {
	name := func(d string) string {
		if n, ok := strings.CutPrefix(d, "sr"); ok {
			return "scd" + n
		}
		return d
	}
	u, f := o.unit()
	devs := rep.shown(o)
	switch {
	case o.Extended && o.Short:
		fmt.Fprintf(w, "Device             tps      %s/s    rqm/s   await aqu-sz  areq-sz  %%util\n", u)
		for _, d := range devs {
			tps, kbs, rqm, await, areq := shortVals(d, false)
			fmt.Fprintf(w, "%-13s %8.2f %9.2f %8.2f %7.2f %6.2f %8.2f %6.2f\n", name(d.Device), tps, kbs/f, rqm, await, d.AquSz, areq, d.Util)
		}
	case o.Extended:
		fmt.Fprintf(w, "Device            r/s     w/s     r%[1]s/s     w%[1]s/s   rrqm/s   wrqm/s  %%rrqm  %%wrqm r_await w_await aqu-sz rareq-sz wareq-sz  svctm  %%util\n", u)
		for _, d := range devs {
			svctm := 0.0
			if ios := d.RS + d.WS; ios > 0 {
				svctm = d.Util * 10 / ios
			}
			fmt.Fprintf(w, "%-13s %7.2f %7.2f %9.2f %9.2f %8.2f %8.2f %6.2f %6.2f %7.2f %7.2f %6.2f %8.2f %8.2f %6.2f %6.2f\n",
				name(d.Device), d.RS, d.WS, d.RKBS/f, d.WKBS/f, d.RRQMS, d.WRQMS, d.RRQMPct, d.WRQMPct, d.RAwait, d.WAwait, d.AquSz,
				d.RAreqSz, d.WAreqSz, svctm, d.Util)
		}
	default:
		fmt.Fprintf(w, "Device             tps    %[1]s_read/s    %[1]s_wrtn/s    %[1]s_read    %[1]s_wrtn\n", u)
		for _, d := range devs {
			fmt.Fprintf(w, "%-13s %8.2f %12.2f %12.2f %10d %10d\n", name(d.Device), d.TPS, d.RKBS/f, d.WKBS/f,
				int64(float64(d.KBRead)/f), int64(float64(d.KBWrtn)/f))
		}
	}
}
