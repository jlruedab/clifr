package recorder

import (
	"errors"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"clifr/internal/rtnl"
	"clifr/internal/store"
)

// netWatch records the interface addresses, routes and policy routing rules:
// a snapshot at the start, in every UTC hour (store.OtherHour) and after lost
// notifications, and in between each change the kernel announces, at the
// time it does. Routes and rules are also dumped again about a second after
// changes (at most every routeRedumpMS), so the kernel's order of them (which
// ip prints) is recorded too; not when there are more than routeRedumpMax
// routes, where a dump costs too much to repeat.
type netWatch struct {
	mu      sync.Mutex
	addrs   []store.AddrRow
	routing []store.RoutingRow
	seq     int // orders the changes of one millisecond
	routes  int // routes in the last dump
}

const (
	routeRedumpMS  = 10_000
	routeRedumpMax = 50_000
)

func (w *netWatch) take() ([]store.AddrRow, []store.RoutingRow) {
	w.mu.Lock()
	defer w.mu.Unlock()
	a, r := w.addrs, w.routing
	w.addrs, w.routing = nil, nil
	return a, r
}

func addrRow(ts int64, action string, seq int, a *rtnl.Addr) store.AddrRow {
	return store.AddrRow{TS: ts, Action: action, Seq: seq, Family: a.Family, PrefixLen: a.PrefixLen, Scope: a.Scope,
		Index: a.Index, Flags: int64(a.Flags), Local: a.Local, Address: a.Address, Broadcast: a.Broadcast,
		Anycast: a.Anycast, Multicast: a.Multicast, Label: a.Label, Metric: a.Metric, Proto: a.Proto,
		Valid: a.Valid, Preferred: a.Preferred}
}

func routingRow(ts int64, action string, seq int, m *rtnl.Message) store.RoutingRow {
	r := store.RoutingRow{TS: ts, Action: action, Seq: seq, Msg: m.Body}
	if len(m.Body) > 0 {
		r.Family = int(m.Body[0])
	}
	switch m.Type {
	case rtnl.RTMNewRoute, rtnl.RTMDelRoute:
		r.Kind, r.Key = "route", rtnl.RouteKey(m.Body)
	default:
		r.Kind, r.Key = "rule", rtnl.RuleKey(m.Body)
	}
	return r
}

// snapshotAddrs writes every address as "present".
func (w *netWatch) snapshotAddrs() error {
	addrs, err := rtnl.DumpAddrs()
	if err != nil {
		return err
	}
	ts := time.Now().UnixMilli()
	rows := make([]store.AddrRow, len(addrs))
	for i := range addrs {
		rows[i] = addrRow(ts, "present", i, &addrs[i])
	}
	w.mu.Lock()
	w.addrs = append(w.addrs, rows...)
	w.mu.Unlock()
	return nil
}

// snapshotRouting writes every route and rule, IPv4 and IPv6, as "present".
func (w *netWatch) snapshotRouting() error {
	var all []rtnl.Message
	routes := 0
	for _, dump := range []func(int) ([]rtnl.Message, error){rtnl.DumpRoutes, rtnl.DumpRules} {
		for _, fam := range []int{unix.AF_INET, unix.AF_INET6} {
			m, err := dump(fam)
			if err != nil {
				return err
			}
			all = append(all, m...)
			if len(m) > 0 && m[0].Type == rtnl.RTMNewRoute {
				routes += len(m)
			}
		}
	}
	ts := time.Now().UnixMilli()
	rows := make([]store.RoutingRow, len(all))
	for i := range all {
		rows[i] = routingRow(ts, "present", i, &all[i])
	}
	w.mu.Lock()
	w.routing = append(w.routing, rows...)
	w.routes = routes
	w.mu.Unlock()
	return nil
}

// startNet subscribes to address, route and rule changes and takes the
// first snapshots.
func (r *Recorder) startNet(done <-chan struct{}) (stop func()) {
	if r.fs.Root != "/proc" {
		return nil // fixtures: netlink would describe this machine
	}
	mon, err := rtnl.NewMonitor(rtnl.GroupIPv4Addr | rtnl.GroupIPv6Addr | rtnl.GroupIPv4Route | rtnl.GroupIPv6Route |
		rtnl.GroupIPv4Rule | rtnl.GroupIPv6Rule)
	if err != nil {
		r.log.Warnf("address and route changes not recorded: %v", err)
		return nil
	}
	w := &netWatch{}
	// After subscribing: no change is missed in between.
	if err := w.snapshotAddrs(); err != nil {
		mon.Close()
		r.log.Warnf("addresses not recorded: %v", err)
		return nil
	}
	if err := w.snapshotRouting(); err != nil {
		r.log.Warnf("routes and rules: %v", err)
	}
	r.net = w
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1<<20)
		fds := []unix.PollFd{{Fd: int32(mon.Fd()), Events: unix.POLLIN}}
		last, lastRouting := time.Now(), time.Now()
		var redump time.Time // when routes and rules are to be dumped again (zero: not due)
		snapshot := func(addrs, routing bool) {
			if addrs {
				if err := w.snapshotAddrs(); err != nil {
					r.log.Errorf("address snapshot: %v", err)
				}
			}
			if routing {
				if err := w.snapshotRouting(); err != nil {
					r.log.Errorf("route snapshot: %v", err)
				}
				lastRouting, redump = time.Now(), time.Time{}
			}
		}
		for {
			select {
			case <-done:
				return
			default:
			}
			if store.OtherHour(last.UnixMilli(), time.Now().UnixMilli()) {
				snapshot(true, true)
				last = time.Now()
			}
			if !redump.IsZero() && time.Now().After(redump) {
				snapshot(false, true)
			}
			if n, err := unix.Poll(fds, 500); err != nil && err != unix.EINTR {
				r.log.Errorf("network watch: %v", err)
				return
			} else if n <= 0 {
				continue
			}
			addrs, routing, err := mon.ReadMessages(buf)
			switch {
			case errors.Is(err, rtnl.ErrOverflow):
				r.log.Warnf("address or route changes lost (kernel buffer overflow): taking new snapshots")
				snapshot(true, true)
				last = time.Now()
				continue
			case err != nil:
				r.log.Errorf("network watch: %v", err)
				return
			}
			ts := time.Now().UnixMilli()
			w.mu.Lock()
			for i := range addrs {
				action := "add"
				if addrs[i].Deleted {
					action = "del"
				}
				w.seq++
				w.addrs = append(w.addrs, addrRow(ts, action, w.seq, &addrs[i]))
			}
			for i := range routing {
				action := "add"
				if routing[i].Type == rtnl.RTMDelRoute || routing[i].Type == rtnl.RTMDelRule {
					action = "del"
				}
				w.seq++
				w.routing = append(w.routing, routingRow(ts, action, w.seq, &routing[i]))
			}
			small := w.routes <= routeRedumpMax
			w.mu.Unlock()
			if len(routing) > 0 && small && redump.IsZero() {
				redump = time.Now().Add(time.Second)
				if earliest := lastRouting.Add(routeRedumpMS * time.Millisecond); earliest.After(redump) {
					redump = earliest
				}
			}
		}
	}()
	return func() { wg.Wait(); mon.Close() }
}
