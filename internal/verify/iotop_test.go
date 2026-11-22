package verify

import (
	"testing"
)

// TestParseIotop: the Python iotop's builds, lines from the VM captures
// (bench/results/iotop-captures-20261122): RHEL 8 (b'...', delay
// accounting), Ubuntu 22.04 (0.6-24) and clifr's own "?" for SWAPIN.
func TestParseIotop(t *testing.T) {
	rhel := `Total DISK READ :       0.00 B/s | Total DISK WRITE :       0.00 B/s
Actual DISK READ:       0.00 B/s | Actual DISK WRITE:       0.00 B/s
    PID  PRIO  USER     DISK READ  DISK WRITE  SWAPIN      IO    COMMAND
Total DISK READ :     545.62 B/s | Total DISK WRITE :       8.53 K/s
Actual DISK READ:     159.85 M/s | Actual DISK WRITE:     166.53 M/s
    PID  PRIO  USER     DISK READ  DISK WRITE  SWAPIN      IO    COMMAND
b'    794 idle root      545.62 B/s    8.53 K/s  0.00 %  0.00 % clifrd'
b'   9435 be/4 root        0.00 B/s    0.00 B/s  0.00 %  0.01 % [kworker/2:3-events_freezable_power_]'
b"   1200 ?dif root        0.00 B/s    0.00 B/s  0.00 % 12.50 % sh -c 'x'"
`
	tot, rows := parseIotop(rhel, 1)
	if tot["Total"] != [2]float64{545.62, 8.53 * 1024} || tot["Actual"][1] != 166.53*1024*1024 {
		t.Errorf("totals: %v", tot)
	}
	if r := rows[794]; r.prio != "idle" || r.user != "root" || r.read != 545.62 || r.io != 0 || r.cmd != "clifrd" {
		t.Errorf("794: %+v", r)
	}
	if r := rows[9435]; r.io != 0.01 || r.cmd != "[kworker/2:3-events_freezable_power_]" {
		t.Errorf("9435: %+v", r)
	}
	if r := rows[1200]; r.prio != "?dif" || r.io != 12.5 || r.cmd != "sh -c 'x'" {
		t.Errorf("1200: %+v", r)
	}
	ubuntu := `Total DISK READ:         0.00 B/s | Total DISK WRITE:        28.60 K/s
Current DISK READ:       0.00 B/s | Current DISK WRITE:       1.98 M/s
    PID  PRIO  USER     DISK READ  DISK WRITE  SWAPIN      IO    COMMAND
    349 be/3 root        0.00 B/s    7.98 K/s  ?unavailable?  [jbd2/vda1-8]
   1796 be/4 root        0.00 B/s 2038.60 B/s ?unavailable?  python3 /usr/sbin/iotop-py -b -P -o -n 3 -d 2
    700 be/4 root        1.00 K/s    0.00 B/s       ?  3.00 % x y`
	tot, rows = parseIotop(ubuntu, 0)
	if tot["Actual"][1] != 1.98*1024*1024 {
		t.Errorf("totals: %v", tot)
	}
	if r := rows[349]; r.write != 7.98*1024 || r.io != -1 || r.cmd != "[jbd2/vda1-8]" {
		t.Errorf("349: %+v", r)
	}
	if r := rows[1796]; r.write != 2038.6 || r.cmd != "python3 /usr/sbin/iotop-py -b -P -o -n 3 -d 2" {
		t.Errorf("1796: %+v", r)
	}
	if r := rows[700]; r.io != 3 || r.cmd != "x y" {
		t.Errorf("700 (clifr's SWAPIN): %+v", r)
	}
	if _, rows := parseIotop(ubuntu, 1); rows != nil {
		t.Error("no second screen: rows")
	}
}
