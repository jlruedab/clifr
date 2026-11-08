package main

// clifr license: the commercial licence clifr --host needs (phase 7.3).
// Checked offline against the public keys built into clifr.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"clifr/internal/license"
	"clifr/internal/query"
)

// systemLicense is the spec's default licence file.
const systemLicense = "/etc/clifr/clifr.lic"

// userLicense is where `clifr license install` puts a user's licence.
func userLicense() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "clifr", "license")
}

// licensePaths are where a licence is looked for, in order: --license or
// CLIFR_LICENSE alone if given, else the user's file, then the system's.
func licensePaths(g *globals) []string {
	if g.lic != "" {
		return []string{g.lic}
	}
	var out []string
	if u := userLicense(); u != "" {
		out = append(out, u)
	}
	return append(out, systemLicense)
}

// findLicense returns the first licence file found and its parsed licence.
// fs.ErrNotExist: none; another error: the file found is not valid.
func findLicense(g *globals) (string, *license.License, error) {
	for _, p := range licensePaths(g) {
		b, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) && g.lic == "" {
			continue
		}
		if err != nil {
			return p, nil, err
		}
		l, err := license.Parse(b, license.Keys())
		return p, l, err
	}
	return "", nil, fs.ErrNotExist
}

// checkRemoteLicense is the gate of clifr --host (the user, 2026-11-08: all
// of --host needs a commercial licence; local data never does). Checked
// before any connection. An expired licence warns and goes on.
func checkRemoteLicense(g *globals) error {
	const terms = "Querying another host (clifr --host) needs a commercial licence; local recordings, bundles and " +
		"sosreports (--data-dir) do not.\nLicensing: see LICENSING.md (/usr/share/doc/clifr/LICENSING.md); " +
		"install a licence with: clifr license install FILE"
	// Dormant in a build without the issuer's public key (the user,
	// 2026-11-08: merged before the production key exists; adding the key to
	// license.productionKeys turns the gate on).
	if len(license.Keys()) == 0 {
		return nil
	}
	p, l, err := findLicense(g)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("no licence installed (looked in %s).\n%s", strings.Join(licensePaths(g), ", "), terms)
	case err != nil:
		return fmt.Errorf("licence %s: %w.\n%s", p, err, terms)
	case !l.Has(license.FeatureRemote):
		return fmt.Errorf("licence %s (%s, for %s) does not include remote queries (features: %s).\n%s",
			l.ID, p, l.Customer, featureList(l), terms)
	}
	if l.Expired(time.Now()) {
		query.Header("licence %s of %s expired on %s (clifr --host keeps working; renew it%s)", l.ID, l.Customer, l.Expires, contactHint(l))
	}
	return nil
}

func licenseCmd(g *globals, args []string) error {
	verb := "show"
	if len(args) > 0 {
		verb = args[0]
	}
	switch verb {
	case "show", "key":
		if len(args) > 1 {
			return usageError{fmt.Errorf("clifr license %s: unexpected %q", verb, args[1])}
		}
		return showLicense(g)
	case "install":
		if len(args) != 2 {
			return usageError{errors.New("usage: clifr license install FILE")}
		}
		return installLicense(args[1])
	}
	return usageError{fmt.Errorf("clifr license: unknown %q (show, or install FILE)", verb)}
}

func showLicense(g *globals) error {
	p, l, err := findLicense(g)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("no licence installed (looked in %s).\n"+
			"Querying another host (clifr --host) needs a commercial licence; local recordings, bundles and sosreports do not.\n"+
			"Install one with: clifr license install FILE", strings.Join(licensePaths(g), ", "))
	case err != nil:
		return fmt.Errorf("%s: %w", p, err)
	}
	status := "valid"
	exp := "never"
	if l.Expires != "" {
		exp = l.Expires
		if l.Expired(time.Now()) {
			status = "expired (clifr --host keeps working; renew it" + contactHint(l) + ")"
		}
	}
	fmt.Printf("Licence:   %s\nID:        %s\nCustomer:  %s\n", p, l.ID, l.Customer)
	if l.Contact != "" {
		fmt.Printf("Contact:   %s\n", l.Contact)
	}
	fmt.Printf("Issued:    %s\nExpires:   %s\nFeatures:  %s\nStatus:    %s\n", l.Issued, exp, featureList(l), status)
	return nil
}

func contactHint(l *license.License) string {
	if l.Contact == "" {
		return ""
	}
	return ": " + l.Contact
}

func featureList(l *license.License) string {
	var out []string
	for _, f := range l.Features {
		if f == license.FeatureRemote {
			f += " (clifr --host)"
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ", ")
}

// installLicense checks FILE and installs it: system-wide as root, else for
// the user. An invalid licence is not installed.
func installLicense(file string) error {
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	l, err := license.Parse(b, license.Keys())
	if err != nil {
		return fmt.Errorf("%s: %w; not installed", file, err)
	}
	dst := userLicense()
	if os.Geteuid() == 0 {
		dst = systemLicense
	}
	if dst == "" {
		return errors.New("no configuration directory for the licence (HOME not set)")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	fmt.Fprintf(os.Stderr, "clifr: licence %s for %s installed in %s\n", l.ID, l.Customer, dst)
	if l.Expired(time.Now()) {
		fmt.Fprintf(os.Stderr, "clifr: it expired on %s (clifr --host keeps working)\n", l.Expires)
	}
	return nil
}
