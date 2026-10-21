package query

import (
	"strings"
	"testing"

	"clifr/internal/store"
)

func TestPrintListUnits(t *testing.T) {
	units := []store.UnitRow{
		{Name: "sshd.service", Description: "OpenSSH server daemon", Load: "loaded", Active: "active", Sub: "running"},
		{Name: "boot.mount", Load: "not-found", Active: "inactive", Sub: "dead"},
		{Name: "bad.service", Description: "Bad", Load: "loaded", Active: "failed", Sub: "failed"},
		{Name: "dev-sda.device", Description: "Disk", Load: "loaded", Active: "active", Sub: "plugged", Following: "sys-x.device"},
		{Name: "idle.timer", Description: "Idle", Load: "loaded", Active: "inactive", Sub: "dead", JobID: 7, JobType: "start"},
	}
	for _, c := range []struct {
		style string
		o     ListUnitsOptions
		want  string
	}{
		{"current", ListUnitsOptions{ASCII: true},
			"  UNIT         LOAD   ACTIVE   SUB     JOB   DESCRIPTION\n" +
				"* bad.service  loaded failed   failed  -     Bad\n" +
				"  sshd.service loaded active   running -     OpenSSH server daemon\n" +
				"  idle.timer   loaded inactive dead    start Idle\n\n" +
				"Legend: LOAD   -> Reflects whether the unit definition was properly loaded.\n" +
				"        ACTIVE -> The high-level unit activation state, i.e. generalization of SUB.\n" +
				"        SUB    -> The low-level unit activation state, values depend on unit type.\n" +
				"        JOB    -> Pending job for the unit.\n\n" +
				"3 loaded units listed. Pass --all to see loaded but inactive units, too.\n" +
				"To show all installed unit files use 'systemctl list-unit-files'.\n"},
		{"rhel-9", ListUnitsOptions{States: []string{"failed"}},
			"  UNIT        LOAD   ACTIVE SUB    DESCRIPTION\n" +
				"● bad.service loaded failed failed Bad\n\n" +
				"LOAD   = Reflects whether the unit definition was properly loaded.\n" +
				"ACTIVE = The high-level unit activation state, i.e. generalization of SUB.\n" +
				"SUB    = The low-level unit activation state, values depend on unit type.\n" +
				"1 loaded units listed.\n"},
		{"rhel-8", ListUnitsOptions{All: true, Types: []string{"mount", "device"}},
			"  UNIT           LOAD      ACTIVE   SUB     DESCRIPTION\n" +
				"  dev-sda.device loaded    active   plugged Disk       \n" +
				"● boot.mount     not-found inactive dead               \n\n" +
				"LOAD   = Reflects whether the unit definition was properly loaded.\n" +
				"ACTIVE = The high-level unit activation state, i.e. generalization of SUB.\n" +
				"SUB    = The low-level unit activation state, values depend on unit type.\n\n" +
				"2 loaded units listed.\nTo show all installed unit files use 'systemctl list-unit-files'.\n"},
	} {
		var sb strings.Builder
		PrintListUnits(&sb, units, c.o, Styles[c.style])
		if sb.String() != c.want {
			t.Errorf("%s %+v:\n%s\nwant\n%s", c.style, c.o, sb.String(), c.want)
		}
	}
}
