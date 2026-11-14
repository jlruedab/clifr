package pqstore

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
)

// A full disk (ENOSPC, or the quota: EDQUOT) once stopped clifrd: the flush
// error ended the recorder, which systemd restarted only for it to fail
// again at its next flush, losing the buffered minutes each time and
// freeing nothing. Now a flush that fails for space deletes the store's
// oldest hour (all tables, never the newest diskFullKeep) and tries again,
// up to diskFullHours hours; if the disk is still full (filled by something
// else) clifrd keeps recording into memory, bounded by the memory guard,
// and tries again every diskFullRetry. Guard events and the journal say so.

const (
	diskFullKeep  = 2 * time.Hour
	diskFullHours = 24
	diskFullRetry = time.Minute
)

func noSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}

// Flush writes everything buffered and rewrites the open files (flushOnce),
// making room on a full disk.
func (s *Store) Flush() error {
	err := s.flushOnce()
	var freed []string
	var freedBytes int64
	for i := 0; noSpace(err) && i < diskFullHours; i++ {
		hour, n := s.freeOldestHour(time.Now())
		if hour == "" {
			break
		}
		freed, freedBytes = append(freed, hour), freedBytes+n
		err = s.flushOnce()
	}
	now := time.Now()
	if len(freed) > 0 {
		d := fmt.Sprintf("disk full: deleted the oldest recorded hours %s (UTC, %d bytes) to make room", hourRange(freed), freedBytes)
		if noSpace(err) {
			d += "; still full"
		}
		s.opt.Logf("pqstore: %s", d)
		s.guard = append(s.guard, guardRow{TS: now.UnixMilli(), Kind: "disk_full", Detail: d})
	}
	if noSpace(err) {
		if !s.diskFull {
			d := fmt.Sprintf("disk full: %s; recording into memory (bounded by the memory guard), trying again every %s", oneLine(err), diskFullRetry)
			s.opt.Logf("pqstore: %s", d)
			s.guard = append(s.guard, guardRow{TS: now.UnixMilli(), Kind: "disk_full", Detail: d})
		}
		s.diskFull, s.noSpaceUntil = true, now.Add(diskFullRetry)
		return nil
	}
	if err == nil && s.diskFull {
		s.diskFull = false
		s.opt.Logf("pqstore: disk space again: written")
		s.guard = append(s.guard, guardRow{TS: now.UnixMilli(), Kind: "disk_ok", Detail: "disk space again: the rows held in memory are written"})
	}
	return err
}

// oneLine is a joined error's first line, and how many more there are.
func oneLine(err error) string {
	lines := strings.Split(err.Error(), "\n")
	if len(lines) == 1 {
		return lines[0]
	}
	return fmt.Sprintf("%s (and %d more files)", lines[0], len(lines)-1)
}

func hourRange(h []string) string {
	if len(h) == 1 {
		return h[0]
	}
	return h[0] + " .. " + h[len(h)-1]
}

// freeOldestHour deletes every table's files of the oldest recorded hour,
// unless it is among the newest diskFullKeep or compaction is running (it
// may be merging that hour). It returns the hour ("2006-01-02 15:00", UTC)
// and the bytes freed, or "".
func (s *Store) freeOldestHour(now time.Time) (string, int64) {
	if s.busy.Load() {
		return "", 0
	}
	s.dirs.Lock()
	defer s.dirs.Unlock()
	hours := s.listHours()
	sort.SliceStable(hours, func(i, j int) bool { return hours[i].start().Before(hours[j].start()) })
	if len(hours) == 0 {
		return "", 0
	}
	oldest := hours[0].start()
	if !oldest.Before(now.UTC().Truncate(time.Hour).Add(-diskFullKeep + time.Hour)) {
		return "", 0
	}
	var n int64
	for _, h := range hours {
		if !h.start().Equal(oldest) {
			break
		}
		if st, err := os.Stat(h.path); err == nil {
			n += st.Size()
		}
		os.Remove(h.path)
	}
	return oldest.Format("2006-01-02 15:00"), n
}
