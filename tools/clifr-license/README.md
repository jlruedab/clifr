# clifr-license: issuing commercial licences

The copyright holder's tool for clifr's commercial licences (`clifr --host`
needs one; local data never does). It is built on its own and never
packaged. clifr itself only checks licences, against the public keys built
into it (`internal/license`, `productionKeys`).

```sh
go build -o clifr-license ./tools/clifr-license
```

## The key pair (once)

The private key decides who can issue licences: anyone who has it can make
valid ones for every clifr built with its public key. Make it on a machine
you trust, ideally offline, and keep it off this repository and off shared
disks.

```sh
./clifr-license keygen -out ~/secure/clifr-issuer.key     # mode 600; refuses to overwrite
```

It prints the public key, one line such as `clifr-ed25519:Mk3x...`. That
line is what goes into clifr (`productionKeys` in
`internal/license/license.go`); it is not secret.

Keep two backups of the private key file (one line of 67 bytes: a printout or an
encrypted USB stick both work), in different places. If it is lost, no new
licences can be issued until a new key pair is made and its public key is
added to clifr (licences of the old key stay valid while the old public key
stays in the list). If it leaks, make a new pair, add its public key, and
remove the old one in the next release: licences signed by the old key then
stop working there, so reissue the customers' licences first.

`./clifr-license pubkey -key FILE` prints the public key of a private key
file again.

## Issuing a licence

```sh
./clifr-license sign -key ~/secure/clifr-issuer.key -id CL-2026-0001 -customer "Acme Ltd" \
    -contact licensing@example.com -years 1 -o acme.lic
./clifr-license verify -pub clifr-ed25519:Mk3x... acme.lic
```

`-years N` (or `-expires YYYY-MM-DD`, the last valid day; neither: no end)
sets the expiry. An expired licence only makes clifr print a reminder with
the `-contact`; `--host` keeps working. `-features` defaults to `remote`
(clifr --host). The licence is a text file: send it by mail or paste it in
a ticket. The customer installs it with `clifr license install acme.lic`.

Keep a list of the licences you issued (id, customer, dates): the tool
keeps none.
