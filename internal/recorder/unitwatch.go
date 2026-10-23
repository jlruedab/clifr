package recorder

import (
	"sync"
	"time"

	"github.com/godbus/dbus/v5"

	"clifr/internal/sdunits"
	"clifr/internal/store"
)

// unitWatch records systemd's units: a snapshot at the start and every
// store.NetSnapshotMS, and after systemd signals a change (at most every
// unitListMS, unitQuietMS after the signal) the units that changed.
type unitWatch struct {
	mu   sync.Mutex
	rows []store.UnitRow
	last map[string]sdunits.Unit
}

const (
	unitListMS  = 1000
	unitQuietMS = 200
)

func (w *unitWatch) take() []store.UnitRow {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.rows
	w.rows = nil
	return out
}

func unitRow(ts int64, action string, seq int, u *sdunits.Unit) store.UnitRow {
	return store.UnitRow{TS: ts, Action: action, Seq: seq, Name: u.Name, Description: u.Description, Load: u.Load,
		Active: u.Active, Sub: u.Sub, Following: u.Following, JobID: int64(u.JobID), JobType: u.JobType}
}

// record lists the units: all of them as "present" for a snapshot, else
// those that changed.
func (w *unitWatch) record(c *sdunits.Conn, snapshot bool) error {
	units, err := c.ListUnits()
	if err != nil {
		return err
	}
	ts := time.Now().UnixMilli()
	now := make(map[string]sdunits.Unit, len(units))
	var rows []store.UnitRow
	for i := range units {
		u := &units[i]
		now[u.Name] = *u
		switch prev, ok := w.last[u.Name]; {
		case snapshot:
			rows = append(rows, unitRow(ts, "present", i, u))
		case !ok || prev != *u:
			rows = append(rows, unitRow(ts, "change", i, u))
		}
	}
	if !snapshot {
		for name, u := range w.last {
			if _, ok := now[name]; !ok {
				rows = append(rows, unitRow(ts, "gone", 0, &u))
			}
		}
	}
	w.last = now
	w.mu.Lock()
	w.rows = append(w.rows, rows...)
	w.mu.Unlock()
	return nil
}

// startUnits records systemd's units until done. It connects in the
// background (systemd may not answer for a while: the recorder does not
// wait for it), every 5 s until that works; when the connection closes
// (systemd re-executes itself on upgrades), it connects again and takes a
// new snapshot.
func (r *Recorder) startUnits(done <-chan struct{}) (stop func()) {
	if r.fs.Root != "/proc" {
		return nil // fixtures: systemd is this machine's
	}
	w := &unitWatch{}
	connect := func() (*sdunits.Conn, <-chan *dbus.Signal, error) {
		c, err := sdunits.Open()
		if err != nil {
			return nil, nil, err
		}
		signals, err := c.Subscribe()
		if err == nil {
			err = w.record(c, true) // after subscribing: no change is missed in between
		}
		if err != nil {
			c.Close()
			return nil, nil, err
		}
		return c, signals, nil
	}
	r.units = w
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, signals, err := connect()
		if err != nil {
			r.log.Warnf("systemd units not recorded yet: %v (trying again every 5 s)", err)
			c = nil
		}
		defer func() {
			if c != nil {
				c.Close()
			}
		}()
		connected := c != nil
		lastSnap, lastList := time.Now(), time.Now()
		var due <-chan time.Time // a listing is due (nil: no change signalled)
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case _, ok := <-signals:
				if !ok {
					r.log.Warnf("systemd units: connection closed; connecting again")
					c.Close()
					c, signals, due = nil, nil, nil
					continue
				}
				if due == nil {
					wait := unitQuietMS * time.Millisecond
					if next := time.Until(lastList.Add(unitListMS * time.Millisecond)); next > wait {
						wait = next
					}
					due = time.After(wait)
				}
			case <-due:
				due = nil
				if err := w.record(c, false); err != nil {
					r.log.Errorf("systemd units: %v", err)
				}
				lastList = time.Now()
			case <-tick.C:
				switch {
				case c == nil:
					if c, signals, err = connect(); err != nil {
						c = nil
						continue
					}
					if connected {
						r.log.Printf("systemd units: connected again")
					} else {
						r.log.Printf("systemd units: connected")
					}
					connected = true
					lastSnap, lastList = time.Now(), time.Now()
				case time.Since(lastSnap) >= store.NetSnapshotMS*time.Millisecond:
					if err := w.record(c, true); err != nil {
						r.log.Errorf("systemd units: %v", err)
					}
					lastSnap, lastList = time.Now(), time.Now()
				}
			}
		}
	}()
	return wg.Wait
}
