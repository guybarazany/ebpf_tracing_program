# eBPF Tracing program

A minimal eBPF program and userspace loader that traces a few kernel functions(fork, exit, execve, openat, vfs_write).

# Project Structure
- `trace_exec_bpf.c` – eBPF program running in the kernel.
- `trace_exec.c` – Userspace program that loads and interacts with the eBPF program.
- `Makefile` – Builds both the eBPF and userspace binaries, generates the libbpf skeleton, and creates `vmlinux.h` automatically.
- `.gitignore` – Ignores build artifacts.

# Requirements
Make sure your environment provides:
- Linux kernel **with BTF enabled** (check: `/sys/kernel/btf/vmlinux` exists).
- `clang` and `llvm` (for compiling eBPF).
- `bpftool` (for generating skeleton and `vmlinux.h`).
- `libbpf-dev` (headers + library).
- Root privileges (`sudo`) or capabilities to load BPF programs.

# How to build?
- git clone https://github.com/guybarazany/ebpf_tracing_program.git
- cd ebpf_tracing_program
- make

# How to run? 
- sudo ./trace_exec

