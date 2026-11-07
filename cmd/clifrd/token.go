package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"clifr/internal/remote"
)

// tokenCmd is `clifrd token new|list|revoke`: the access tokens of
// clifrd --serve. Only their SHA-256 is stored; a new token is shown once.
func tokenCmd(args []string) error {
	fs := flag.NewFlagSet("clifrd token", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "clifrd token manages the access tokens of clifrd --serve (clifr --host). The file keeps\n"+
			"only each token's SHA-256; a new token is printed once and cannot be shown again.\n\n"+
			"Usage:\n"+
			"  clifrd token new [--comment TEXT]   create a token (give it to clifr: --token or CLIFR_TOKEN)\n"+
			"  clifrd token list                   the stored hashes and comments\n"+
			"  clifrd token revoke HASH-PREFIX     remove a token (at least 8 hex digits, from list);\n"+
			"                                      clifrd stops accepting it at once\n\nOptions:\n")
		fs.PrintDefaults()
	}
	file := fs.String("file", remote.DefaultTokenFile, "token file (owned by clifrd's user, mode 600)")
	comment := fs.String("comment", "", "new: a note stored with the hash (who or what the token is for)")
	if len(args) == 0 {
		fs.Usage()
		return errors.New("clifrd token: want new, list or revoke")
	}
	verb := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch verb {
	case "new":
		if fs.NArg() > 0 {
			return fmt.Errorf("clifrd token new: unexpected %q (a comment goes in --comment)", fs.Arg(0))
		}
		tok, err := remote.AddToken(*file, *comment)
		if err != nil {
			return err
		}
		fmt.Println(tok)
		fmt.Fprintf(os.Stderr, "clifrd: token added to %s (hash %s...); it is shown only now.\n", *file, remote.Hash(tok)[:12])
		return nil
	case "list":
		b, err := os.ReadFile(*file)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "clifrd: no token file %s (clifrd token new)\n", *file)
			return nil
		}
		if err != nil {
			return err
		}
		lines, err := remote.ParseTokens(b)
		if err != nil {
			return fmt.Errorf("%s: %w", *file, err)
		}
		for _, l := range lines {
			fmt.Printf("%s  %s\n", l.Hash[:12], l.Comment)
		}
		return nil
	case "revoke":
		if fs.NArg() != 1 {
			return errors.New("clifrd token revoke HASH-PREFIX (from clifrd token list)")
		}
		n, err := remote.RevokeToken(*file, fs.Arg(0))
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "clifrd: %d token(s) revoked\n", n)
		return nil
	}
	fs.Usage()
	return fmt.Errorf("clifrd token: unknown %q (new, list or revoke)", verb)
}
