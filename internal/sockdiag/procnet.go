package sockdiag

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ReadProcNet is the fallback when sock_diag is unavailable: it parses
// <procRoot>/net/{tcp,tcp6,udp,udp6}. It is much slower with many sockets,
// and for LISTEN sockets Send-Q (the backlog) is not available (reported 0).
func ReadProcNet(procRoot string) ([]Socket, error) {
	var out []Socket
	for _, f := range []struct {
		name, proto string
		family      int
	}{{"tcp", "tcp", 4}, {"tcp6", "tcp", 6}, {"udp", "udp", 4}, {"udp6", "udp", 6}} {
		fh, err := os.Open(filepath.Join(procRoot, "net", f.name))
		if err != nil {
			if os.IsNotExist(err) {
				continue // e.g. IPv6 disabled
			}
			return nil, err
		}
		out, err = ParseProcNet(fh, f.proto, f.family, out)
		fh.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.name, err)
		}
	}
	return out, nil
}

// ParseProcNet parses one /proc/net/{tcp,udp}[6] file.
//
//	sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode
//	0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 ...
func ParseProcNet(r io.Reader, proto string, family int, out []Socket) ([]Socket, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		if first { // header
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		s := Socket{Proto: proto, Family: family}
		var err error
		if s.LAddr, s.LPort, err = parseHexAddr(f[1]); err != nil {
			return out, err
		}
		if s.RAddr, s.RPort, err = parseHexAddr(f[2]); err != nil {
			return out, err
		}
		st, _ := strconv.ParseUint(f[3], 16, 8)
		s.State = int(st)
		if tx, rx, ok := strings.Cut(f[4], ":"); ok {
			t, _ := strconv.ParseUint(tx, 16, 32)
			r, _ := strconv.ParseUint(rx, 16, 32)
			s.TxQ, s.RxQ = uint32(t), uint32(r)
		}
		uid, _ := strconv.ParseUint(f[7], 10, 32)
		s.UID = uint32(uid)
		s.Inode, _ = strconv.ParseUint(f[9], 10, 64)
		if s.State == 10 { // LISTEN: tx_queue is not the backlog here
			s.TxQ = 0
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

// parseHexAddr decodes "0100007F:0016". Each 32-bit word of the address is
// printed in host byte order.
func parseHexAddr(s string) (netip.Addr, int, error) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("bad address %q", s)
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	raw, err := hex.DecodeString(a)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, 0, fmt.Errorf("bad address %q", s)
	}
	for i := 0; i < len(raw); i += 4 {
		w := binary.NativeEndian.Uint32(raw[i:])
		binary.BigEndian.PutUint32(raw[i:], w)
	}
	if len(raw) == 4 {
		return netip.AddrFrom4([4]byte(raw)), int(port), nil
	}
	return netip.AddrFrom16([16]byte(raw)), int(port), nil
}
