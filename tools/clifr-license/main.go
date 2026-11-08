// Command clifr-license issues clifr's commercial licences (phase 7.3). It is
// the copyright holder's tool: built on its own (go build
// ./tools/clifr-license), never packaged. See README.md here for the key
// ceremony.
//
//	clifr-license keygen -out FILE          a new key pair: the private key in FILE (mode 600),
//	                                        the public key printed (to build into clifr)
//	clifr-license pubkey -key FILE          print the public key of a private key file
//	clifr-license sign -key FILE -id ID -customer NAME [-contact C] [-issued D] [-expires D | -years N]
//	                   [-features remote] [-o FILE]
//	clifr-license verify -pub KEY FILE      check a licence against a public key
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"strings"
	"time"

	"clifr/internal/license"
)

const privPrefix = "clifr-ed25519-private:"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "clifr-license:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("want keygen, pubkey, sign or verify (see the comment at the top of main.go)")
	}
	fs := flag.NewFlagSet("clifr-license "+args[0], flag.ContinueOnError)
	switch args[0] {
	case "keygen":
		file := fs.String("out", "", "file for the private key (created with mode 600; never overwritten)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *file == "" {
			return errors.New("keygen: -out FILE is required")
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, iofs.ErrExist) {
			return fmt.Errorf("keygen: %s exists: not overwriting a key", *file)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(f, "%s%s\n", privPrefix, base64.StdEncoding.EncodeToString(priv.Seed()))
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s\n", license.FormatPublicKey(pub))
		fmt.Fprintf(os.Stderr, "clifr-license: private key in %s (mode 600): keep it offline, with a backup; anyone holding it can issue licences.\n"+
			"The line above is the public key to build into clifr.\n", *file)
		return nil
	case "pubkey":
		file := fs.String("key", "", "private key file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		priv, err := readPrivate(*file)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, license.FormatPublicKey(priv.Public().(ed25519.PublicKey)))
		return nil
	case "sign":
		file := fs.String("key", "", "private key file")
		id := fs.String("id", "", "licence id (e.g. CL-2026-0001)")
		customer := fs.String("customer", "", "customer name")
		contact := fs.String("contact", "", "whom to ask for a renewal (shown when it expires)")
		issued := fs.String("issued", time.Now().UTC().Format("2006-01-02"), "issue date, YYYY-MM-DD")
		expires := fs.String("expires", "", "last valid day, YYYY-MM-DD (empty: no end)")
		years := fs.Int("years", 0, "valid this many years from the issue date (instead of -expires)")
		features := fs.String("features", license.FeatureRemote, "comma-separated features")
		o := fs.String("o", "", "write the licence to this file (default: standard output)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		priv, err := readPrivate(*file)
		if err != nil {
			return err
		}
		exp := *expires
		if *years > 0 {
			if exp != "" {
				return errors.New("sign: -expires or -years, not both")
			}
			d, err := time.Parse("2006-01-02", *issued)
			if err != nil {
				return fmt.Errorf("sign: -issued %q: want YYYY-MM-DD", *issued)
			}
			exp = d.AddDate(*years, 0, -1).Format("2006-01-02")
		}
		text, err := license.Sign(license.License{ID: *id, Customer: *customer, Contact: *contact, Issued: *issued,
			Expires: exp, Features: strings.Split(*features, ",")}, priv)
		if err != nil {
			return err
		}
		if *o == "" {
			_, err = out.Write(text)
			return err
		}
		return os.WriteFile(*o, text, 0o644)
	case "verify":
		var pubs multi
		fs.Var(&pubs, "pub", "public key (clifr-ed25519:...), repeatable")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 || len(pubs) == 0 {
			return errors.New("verify -pub KEY FILE")
		}
		var keys []ed25519.PublicKey
		for _, p := range pubs {
			k, err := license.ParsePublicKey(p)
			if err != nil {
				return err
			}
			keys = append(keys, k)
		}
		b, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			return err
		}
		l, err := license.Parse(b, keys)
		if err != nil {
			return err
		}
		state := "valid"
		if l.Expired(time.Now()) {
			state = "expired"
		}
		fmt.Fprintf(out, "%s for %s, issued %s, expires %s, features %s: %s\n", l.ID, l.Customer, l.Issued,
			orNever(l.Expires), strings.Join(l.Features, ","), state)
		return nil
	}
	return fmt.Errorf("unknown command %q (keygen, pubkey, sign, verify)", args[0])
}

// readPrivate reads a private key file; one readable by others is refused.
func readPrivate(file string) (ed25519.PrivateKey, error) {
	if file == "" {
		return nil, errors.New("-key FILE is required")
	}
	fi, err := os.Stat(file)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: mode %#o: the private key must be readable by its owner only (chmod 600)", file, fi.Mode().Perm())
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(b)), privPrefix))
	if err != nil || len(seed) != ed25519.SeedSize || !strings.HasPrefix(string(b), privPrefix) {
		return nil, fmt.Errorf("%s: not a clifr-license private key", file)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func orNever(s string) string {
	if s == "" {
		return "never"
	}
	return s
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }
