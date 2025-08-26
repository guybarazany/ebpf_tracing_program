BPF_CLANG=clang
BPF_CFLAGS=-g -O2 -target bpf -D__TARGET_ARCH_x86 -I.

all: trace_exec

# Generate vmlinux.h from the kernel's BTF information
# vmlinux.h provides kernel struct definitions for CO-RE relocations
vmlinux.h:
	@echo "Generating vmlinux.h..."
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile the eBPF program (trace_exec_bpf.c) into an object file
trace_exec_bpf.o: trace_exec_bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

# Generate a libbpf skeleton header from the compiled .o
# The skeleton provides convenient C helpers for loading/attaching the program
trace_exec.skel.h: trace_exec_bpf.o
	bpftool gen skeleton $< > $@

# Compile the userspace program (trace_exec.c) that uses the skeleton
trace_exec.o: trace_exec.c trace_exec.skel.h
	clang -g -O2 -Wall -I. -c trace_exec.c -o trace_exec.o

# Link the userspace object into a final executable
trace_exec: trace_exec.o
	clang -g -O2 -Wall -o trace_exec trace_exec.o -lbpf -lelf
	
clean: 
	rm -f *.o *.skel.h trace_exec vmlinux.h
