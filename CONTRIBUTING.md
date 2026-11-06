# Contributing to clifr

Thank you for considering a contribution. Bug reports, test results from other distributions and kernels, and pull requests are all welcome.

## Before you send code: the Contributor License Agreement

clifr is offered under the AGPL-3.0 **and** under a commercial license (see [LICENSING.md](LICENSING.md)). To keep that possible, every code or documentation contribution must be covered by the [Contributor License Agreement](CLA.md) (CLA). You keep the copyright of your contribution; the CLA gives the project's copyright holder the right to distribute it under both licenses.

To agree, include this line in the description of your pull request, or of the first one if you send several:

```
I have read the clifr Contributor License Agreement (CLA.md, version 1.0) and agree to its terms.
```

and sign off each commit with your real name (`git commit -s`), which adds:

```
Signed-off-by: Your Name <you@example.com>
```

If you contribute as part of your job, make sure your employer allows it, or have the employer agree to the CLA as well (see the CLA, section 4).

Pull requests without the CLA statement cannot be merged. Bug reports and discussions need no CLA.

## What makes a contribution easy to accept

- **One change per pull request**, with a description of what it fixes or adds and how you tested it.
- **Tests.** `go test ./...` must pass. Changes to the recorder or the eBPF programs should also pass the eBPF self-test and the end-to-end test (root): see the README's [Tests](README.md#tests) section.
- **Accuracy.** clifr's promise is that its output matches the real tool's. A change to a reconstructed command should say which tool version it was checked against, ideally with `clifr verify`.
- **Hard rules** (from the project's design): `clifrd` stays pure Go and static; `/proc/*/environ` is never read; all `/proc` access goes through `procfs.FS`; no network code in the recorder; new dependencies only after discussion in an issue.
- **eBPF changes**: edit the `.bpf.c` source and regenerate the committed objects with `go generate ./internal/bpfproc ./internal/bpftcp` (clang-18, llvm-18, libbpf-dev).

## Reporting security issues

Please do not open a public issue for a vulnerability. Write to <jlrueda@gmail.com> with the details; you will get an answer before anything is published.
