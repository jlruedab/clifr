package pqstore

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"math/bits"
	"os"
	"slices"
)

// connVersion is what compaction reads of tcp_conns first.
type connVersion struct {
	ID       int64 `parquet:"id"`
	LastSeen int64 `parquet:"last_seen,optional"`
}

// mergeConns is merge for tcp_conns, without the versions of a connection
// that a newer one in the same hour replaces. A connection closed in one
// flush and ended its time-wait in the next is written twice (the
// recorder merges versions only within a flush): 26% of the rows of a busy
// hour (2026-11-21). The versions differ only in linger_state,
// linger_until and last_seen, and readers keep the newest last_seen
// (internal/duck, closed rows before open ones; every row here is closed).
// A row is dropped only when the hour has a row of its id with a later
// last_seen: rows tied at the newest stay, a NULL (0) is the oldest, as
// DuckDB's NULLS LAST.
//
// Memory does not grow with the hour's rows: the ids are read three times
// (only id and last_seen), into bitmaps of 1024 ids, and only ids with
// more than one row get a newest last_seen (8 bytes).
func mergeConns(parts []string, out string) error {
	var ids idBits
	if err := readVersions(parts, ids.add); err != nil {
		return err
	}
	n := ids.rank()
	if n == 0 {
		return merge[tcpConnRow](parts, out)
	}
	newest := make([]int64, n)
	for i := range newest {
		newest[i] = -1
	}
	if err := readVersions(parts, func(v connVersion) {
		if i, ok := ids.dupIndex(v.ID); ok {
			newest[i] = max(newest[i], v.LastSeen)
		}
	}); err != nil {
		return err
	}
	return mergeKeep(parts, out, func(r *tcpConnRow) bool {
		i, ok := ids.dupIndex(r.ID)
		return !ok || r.LastSeen >= newest[i]
	})
}

// readVersions calls fn with each row's id and last_seen.
func readVersions(parts []string, fn func(connVersion)) error {
	buf := make([]connVersion, 4096)
	for _, p := range parts {
		if err := CheckFile(p); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		r, err := newReader[connVersion](f)
		if err == nil {
			err = readSafely(p, func() error {
				for {
					n, err := r.Read(buf)
					for _, v := range buf[:n] {
						fn(v)
					}
					if errors.Is(err, io.EOF) {
						return nil
					}
					if err != nil {
						return err
					}
				}
			})
			r.Close()
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// idBits is a set of ids in blocks of 1024 (id >> 10): which were seen, and
// which more than once. A busy hour's ids are dense (they are run start ×
// 1e9 + a counter); a long-lived connection costs one block.
type idBits struct {
	blocks map[int64]*idBlock
}

type idBlock struct {
	seen, dup [16]uint64
	before    [16]int32 // ids with more than one row before this word, over all blocks
}

func (s *idBits) add(v connVersion) {
	if s.blocks == nil {
		s.blocks = map[int64]*idBlock{}
	}
	b := s.blocks[v.ID>>10]
	if b == nil {
		b = new(idBlock)
		s.blocks[v.ID>>10] = b
	}
	w, m := v.ID>>6&15, uint64(1)<<(v.ID&63)
	if b.seen[w]&m != 0 {
		b.dup[w] |= m
	}
	b.seen[w] |= m
}

// rank numbers the ids with more than one row and returns how many there
// are.
func (s *idBits) rank() int {
	n := int32(0)
	for _, k := range slices.Sorted(maps.Keys(s.blocks)) {
		b := s.blocks[k]
		for w := range b.dup {
			b.before[w] = n
			n += int32(bits.OnesCount64(b.dup[w]))
		}
	}
	return int(n)
}

// dupIndex is the number rank gave id, if it has more than one row.
func (s *idBits) dupIndex(id int64) (int, bool) {
	b := s.blocks[id>>10]
	if b == nil {
		return 0, false
	}
	w, m := id>>6&15, uint64(1)<<(id&63)
	if b.dup[w]&m == 0 {
		return 0, false
	}
	return int(b.before[w]) + bits.OnesCount64(b.dup[w]&(m-1)), true
}
