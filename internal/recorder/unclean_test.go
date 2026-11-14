package recorder

import (
	"strings"
	"testing"
	"time"

	"clifr/internal/pqstore"
)

type prevRunOf pqstore.PrevRun

func (p prevRunOf) PrevRun() (pqstore.PrevRun, bool) { return pqstore.PrevRun(p), p.Run != 0 }

// TestUncleanStop: the guard event says whether the machine went down or
// clifrd alone, and when the last sample on disk was; a clean stop, an old
// run without the marker and no run at all give none.
func TestUncleanStop(t *testing.T) {
	last := time.Date(2026, 11, 14, 3, 4, 5, 0, time.Local).UnixMilli()
	for _, c := range []struct {
		name string
		p    pqstore.PrevRun
		want string // "" = no event
	}{
		{"new boot", pqstore.PrevRun{Run: 1, BootID: "A", Known: true, LastSampleMS: last}, "the system went down without a clean shutdown"},
		{"same boot", pqstore.PrevRun{Run: 1, BootID: "B", Known: true, LastSampleMS: last}, "clifrd was killed or crashed while the system kept running"},
		{"clean", pqstore.PrevRun{Run: 1, BootID: "A", Known: true, Clean: true}, ""},
		{"older clifrd", pqstore.PrevRun{Run: 1, BootID: "A"}, ""},
		{"first run", pqstore.PrevRun{}, ""},
	} {
		g, ok := uncleanStop(prevRunOf(c.p), "B", 5*time.Minute)
		switch {
		case c.want == "" && ok:
			t.Errorf("%s: unexpected event %q", c.name, g.Detail)
		case c.want != "" && (!ok || g.Kind != "unclean_stop" || !strings.Contains(g.Detail, c.want) ||
			!strings.Contains(g.Detail, "last sample on disk at 2026-11-14 03:04:05")):
			t.Errorf("%s: %v %q", c.name, ok, g.Detail)
		}
	}
}
