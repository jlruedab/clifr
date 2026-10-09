package bpfproc

// The compiled BPF objects are committed; regenerate after changing
// procevents.bpf.c (needs clang and llvm-strip, e.g. clang-18 and llvm-18):
//
//	go generate ./internal/bpfproc

//go:generate go tool bpf2go -cc clang-18 -strip llvm-strip-18 -target bpfel -type event procRB procevents.bpf.c -- -O2 -g -I/usr/include/x86_64-linux-gnu
//go:generate go tool bpf2go -cc clang-18 -strip llvm-strip-18 -target bpfel procPerf procevents.bpf.c -- -O2 -g -DUSE_PERF -I/usr/include/x86_64-linux-gnu
