# Contributing to clifr

Thank you for considering a contribution. Bug reports, test results from other distributions and kernels, and pull requests are all welcome.

## Before you send code: sign off your commits (DCO)

clifr is licensed under the AGPL-3.0, with the eBPF programs and the sos plugin under their own licenses (see [LICENSING.md](LICENSING.md)); a contribution is made under the license of the files it changes. There is no agreement to sign. Instead, every commit carries a sign-off with your real name, certifying the [Developer Certificate of Origin](DCO) (version 1.1): that you wrote the change, or otherwise have the right to submit it under the project's open-source license.

Sign off with `git commit -s`, which adds:

```
Signed-off-by: Your Name <you@example.com>
```

If you contribute as part of your job, make sure your employer allows it. Pull requests with commits that are not signed off cannot be merged; bug reports and discussions need no sign-off.

## What makes a contribution easy to accept

- **One change per pull request**, with a description of what it fixes or adds and how you tested it.
- **Tests.** `go test ./...` must pass. Changes to the recorder or the eBPF programs should also pass the eBPF self-test and the end-to-end test (root): see the README's [Tests](README.md#tests) section.
- **Accuracy.** clifr's promise is that its output matches the real tool's. A change to a reconstructed command should say which tool version it was checked against, ideally with `clifr verify`.
- **Hard rules** (from the project's design): `clifrd` stays pure Go and static; `/proc/*/environ` is never read; all `/proc` access goes through `procfs.FS`; no network code in the recorder; new dependencies only after discussion in an issue.
- **eBPF changes**: edit the `.bpf.c` source and regenerate the committed objects with `go generate ./internal/bpfproc ./internal/bpftcp` (clang-18, llvm-18, libbpf-dev).

## Reporting security issues

Please do not open a public issue for a vulnerability. Write to <jlrueda@gmail.com> with the details; you will get an answer before anything is published.
