package cnproc

import (
	"encoding/binary"
	"testing"
)

func msg(what uint32, ts uint64, data ...uint32) []byte {
	ne := binary.NativeEndian
	b := make([]byte, nlHdrLen+cnMsgLen+16+4*len(data))
	ne.PutUint32(b[0:], uint32(len(b)))
	c := b[nlHdrLen:]
	ne.PutUint32(c[0:], cnIdxProc)
	ne.PutUint32(c[4:], cnValProc)
	p := c[cnMsgLen:]
	ne.PutUint32(p[0:], what)
	ne.PutUint64(p[8:], ts)
	for i, d := range data {
		ne.PutUint32(p[16+4*i:], d)
	}
	return b
}

func TestParse(t *testing.T) {
	var b []byte
	b = append(b, msg(evFork, 100, 10, 10, 20, 20)...)          // process fork
	b = append(b, msg(evFork, 101, 10, 10, 21, 20)...)          // thread creation: dropped
	b = append(b, msg(evExec, 102, 20, 20)...)                  // exec
	b = append(b, msg(evExit, 103, 21, 20, 0, 17)...)           // thread exit: dropped
	b = append(b, msg(evExit, 104, 20, 20, 256, 17, 10, 10)...) // process exit
	b = append(b, msg(0x200, 105, 20, 20)...)                   // comm change: ignored
	got := Parse(b)
	want := []Event{
		{Kind: Fork, PID: 20, ParentPID: 10, TimestampNS: 100},
		{Kind: Exec, PID: 20, TimestampNS: 102},
		{Kind: Exit, PID: 20, TimestampNS: 104, ExitCode: 256},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v want %+v", i, got[i], want[i])
		}
	}
}
