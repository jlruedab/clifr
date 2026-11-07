package query

import (
	"os/user"
	"strconv"
	"testing"

	"clifr/internal/store"
	"clifr/internal/testrec"
)

// The recorded host's names, not this machine's: a recording read on
// another machine (clifr --host, a bundle) named its users from the local
// passwd until 2026-11-08 (a VM's rpcbind, uid 558 _rpc, showed as
// nvidia-+ here).
func TestRecordedUserNames(t *testing.T) {
	base := int64(1_790_000_000_000)
	snap := func(ts int64, uid, name string, pos int) store.SnapshotRow {
		return store.SnapshotRow{TS: ts, Source: "passwd", Key: uid, Pos: pos, Full: true, Line: uid + " " + name}
	}
	db := testrec.Open(t, nil,
		&store.Batch{Sample: store.Sample{TS: base}, Snapshots: []store.SnapshotRow{snap(base, "0", "root", 0), snap(base, "558", "_rpc", 1),
			snap(base, "100", "systemd-network", 2)}},
		&store.Batch{Sample: store.Sample{TS: base + 60_000}, Snapshots: []store.SnapshotRow{
			{TS: base + 60_000, Source: "passwd", Key: "558", Pos: 1, Line: "558 rpcuser"}}}) // renamed later
	defer func() { recordedUsers, userCache = nil, map[int]string{} }()

	if ok, err := LoadUsers(db, base+30_000); err != nil || !ok {
		t.Fatalf("LoadUsers: %v %v", ok, err)
	}
	for uid, want := range map[int]string{0: "root", 558: "_rpc", 100: "systemd+", 4242: "4242"} {
		if got := UserName(uid, true); got != want {
			t.Errorf("uid %d: %q, want %q", uid, got, want)
		}
	}
	LoadUsers(db, base+90_000) // after the rename
	if got := UserName(558, false); got != "rpcuser" {
		t.Errorf("after the rename: %q", got)
	}
	LoadUsers(db, base-1000) // before the first copy: the first one after
	if got := UserName(558, false); got != "_rpc" {
		t.Errorf("before the first copy: %q", got)
	}

	// No names recorded: this machine's, as before.
	old := testrec.Open(t, nil, &store.Batch{Sample: store.Sample{TS: base}})
	if ok, _ := LoadUsers(old, base); ok {
		t.Fatal("names found in a recording without them")
	}
	want := "0"
	if u, err := user.LookupId("0"); err == nil {
		want = u.Username
	}
	if got := UserName(0, false); got != want {
		t.Errorf("without recorded names: %q, want this machine's %q", got, strconv.Quote(want))
	}
}
