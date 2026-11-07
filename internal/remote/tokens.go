package remote

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// tokenPrefix marks clifr tokens (so they are easy to find in a leak scan).
const tokenPrefix = "clifr_"

// NewToken returns a new random token (256 bits) and the line that stores
// it in the token file: "sha256:HEX comment". The token itself is not kept.
func NewToken(comment string) (token, line string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	token = tokenPrefix + base64.RawURLEncoding.EncodeToString(b[:])
	comment = strings.Join(strings.Fields(comment), " ") // one line
	line = "sha256:" + Hash(token)
	if comment != "" {
		line += " " + comment
	}
	return token, line, nil
}

// Hash is the hex SHA-256 of a token, as the token file stores it.
func Hash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// TokenLine is one entry of the token file.
type TokenLine struct {
	Hash    string // hex SHA-256
	Comment string
}

// ParseTokens reads a token file: one "sha256:HEX [comment]" per line;
// empty lines and lines starting with # are skipped.
func ParseTokens(b []byte) ([]TokenLine, error) {
	var out []TokenLine
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		h, comment, _ := strings.Cut(line, " ")
		hx, ok := strings.CutPrefix(h, "sha256:")
		if d, err := hex.DecodeString(hx); !ok || err != nil || len(d) != sha256.Size {
			return nil, fmt.Errorf("line %d: want sha256:<64 hex digits> [comment]", n)
		}
		out = append(out, TokenLine{Hash: strings.ToLower(hx), Comment: strings.TrimSpace(comment)})
	}
	return out, sc.Err()
}

// checkPerm refuses a token file that others can write or read: it decides
// who reads every process's command line.
func checkPerm(path string, fi fs.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s: mode %#o: must not be readable or writable by group or others (chmod 600)", path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s: owned by uid %d, not by clifrd's user (uid %d): another user could add tokens", path, st.Uid, os.Geteuid())
	}
	return nil
}

// Tokens checks tokens against a token file, re-read when it changes (a
// revoked token stops working without a restart).
type Tokens struct {
	path string
	mu   sync.Mutex
	mod  time.Time
	size int64
	mode fs.FileMode // a chmod changes neither mtime nor size
	sums [][sha256.Size]byte
	err  error
}

// LoadTokens reads path. An error: a missing, unsafe or empty file (clifrd
// does not serve without a token).
func LoadTokens(path string) (*Tokens, error) {
	t := &Tokens{path: path}
	if err := t.reload(); err != nil {
		return nil, err
	}
	if len(t.sums) == 0 {
		return nil, fmt.Errorf("%s: no tokens (clifrd token new)", path)
	}
	return t, nil
}

func (t *Tokens) reload() error {
	fi, err := os.Stat(t.path)
	if err != nil {
		return err
	}
	if fi.ModTime().Equal(t.mod) && fi.Size() == t.size && fi.Mode() == t.mode && t.sums != nil {
		return t.err
	}
	t.mod, t.size, t.mode = fi.ModTime(), fi.Size(), fi.Mode()
	if t.err = checkPerm(t.path, fi); t.err != nil {
		t.sums = [][sha256.Size]byte{}
		return t.err
	}
	b, err := os.ReadFile(t.path)
	if err != nil {
		return err
	}
	lines, err := ParseTokens(b)
	if err != nil {
		t.err, t.sums = fmt.Errorf("%s: %w", t.path, err), [][sha256.Size]byte{}
		return t.err
	}
	t.sums = make([][sha256.Size]byte, len(lines))
	for i, l := range lines {
		hex.Decode(t.sums[i][:], []byte(l.Hash))
	}
	return nil
}

// Check reports whether token is in the file. It compares the token's hash
// with every entry in constant time; a file that became unsafe or
// unreadable accepts nothing.
func (t *Tokens) Check(token string) bool {
	if !strings.HasPrefix(token, tokenPrefix) {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.reload(); err != nil {
		return false
	}
	ok := 0
	for i := range t.sums {
		ok |= subtle.ConstantTimeCompare(sum[:], t.sums[i][:])
	}
	return ok == 1
}

// AddToken appends a new token's line to the file (created 0600) and
// returns the token, to be shown once.
func AddToken(path, comment string) (string, error) {
	if fi, err := os.Stat(path); err == nil {
		if err := checkPerm(path, fi); err != nil {
			return "", err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	token, line, err := NewToken(comment)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return "", err
	}
	_, err = f.WriteString(line + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return token, err
}

// RevokeToken removes the entries whose hash starts with prefix (at least
// 8 hex digits, as `clifrd token list` shows them) and returns how many.
func RevokeToken(path, prefix string) (int, error) {
	prefix = strings.ToLower(strings.TrimPrefix(prefix, "sha256:"))
	if len(prefix) < 8 {
		return 0, errors.New("give at least 8 hex digits of the hash (clifrd token list)")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var keep []string
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		h, _, _ := strings.Cut(strings.TrimSpace(line), " ")
		if strings.HasPrefix(strings.TrimPrefix(h, "sha256:"), prefix) {
			n++
			continue
		}
		keep = append(keep, line)
	}
	if n == 0 {
		return 0, fmt.Errorf("no token with hash %s...", prefix)
	}
	tmp := path + ".tmp"
	data := strings.Join(keep, "\n")
	if len(keep) > 0 {
		data += "\n"
	}
	if err := os.WriteFile(tmp, []byte(data), 0o600); err != nil {
		return 0, err
	}
	return n, os.Rename(tmp, path)
}
