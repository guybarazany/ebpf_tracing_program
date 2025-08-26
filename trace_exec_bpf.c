// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common_event.h"

#define ARG_LEN 128

// File type bitmasks, taken from <sys/stat.h>
// S_IFMT   – mask for the file type bits in i_mode in file struct
// S_IFREG  – value indicating a regular file
#define S_IFMT 00170000
#define S_IFREG 0100000

// Define a ring buffer to send events from kernel space to user space.
// BPF_MAP_TYPE_RINGBUF is a special map type optimized for streaming events.
// max_entries sets the ring buffer size (each entry - 1 byte - > 32MB)
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 25);
} events SEC(".maps");

// Tracepoint: sched:sched_process_fork
// Called when a new child task is cloned from a parent task.
// *current* task is the PARENT.
// Child metadata (pid/comm) is provided in the ctx payload.
SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    // Reserve a fixed-size event record from the ring buffer.
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e)
    {
        return 0;
    }

    e->type = EVENT_FORK;
    e->fork.pid = ctx->child_pid;
    e->fork.ppid = ctx->parent_pid;

    bpf_probe_read_kernel_str(e->fork.comm, sizeof(e->fork.comm), ctx->child_comm);
    // submit the event to user space.
    bpf_ringbuf_submit(e, 0);

    return 0;
}

// Tracepoint: sched:sched_process_exit
// Called when a task is exiting.
// Provides the exiting PID, its PPID, and the comm.
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    struct task_struct *task;

    if (!e)
    {
        return 0;
    }

    e->type = EVENT_EXIT;
    e->exit.pid = ctx->pid;

    // Get ppid From current task_struct,
    task = (struct task_struct *)bpf_get_current_task();
    e->exit.ppid = BPF_CORE_READ(task, real_parent, tgid);

    // Copy the current task->comm (process name) into the event.
    // This gives the executable name that is terminating.
    bpf_get_current_comm(e->exit.comm, sizeof(e->exit.comm));

    bpf_ringbuf_submit(e, 0);

    return 0;
}

// Attach to the sys_enter_execve tracepoint - called when a process invokes execve.
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    struct task_struct *task;

    // Get full exe path
    const char *filename = (const char *)ctx->args[0];

    // Get argv arguments
    const char **argv = (const char **)ctx->args[1];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e)
    {
        return 0;
    }

    e->type = EVENT_EXEC;

    // Safely copy a pointer from user space (filename) into kernel context.
    bpf_core_read_user(e->exec.exe_path, sizeof(e->exec.exe_path), filename);

    e->exec.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->exec.comm, sizeof(e->exec.comm));

    task = (struct task_struct *)bpf_get_current_task();
    e->exec.ppid = BPF_CORE_READ(task, real_parent, tgid);

    // Copy up to MAX_ARGS arguments into event->exec.argv
    // Each argument is limited to ARG_LEN characters
#pragma unroll
    for (int i = 0; i < MAX_ARGS; ++i)
    {
        const char *argp = NULL;
        if (bpf_core_read_user(&argp, sizeof(argp), &argv[i]) != 0)
        {
            break;
        }

        if (!argp)
        {
            break;
        }

        bpf_core_read_user(&e->exec.argv[i], ARG_LEN, argp);
    }

    bpf_ringbuf_submit(e, 0);

    return 0;
}

// Tracepoint handler for sys_enter_openat
// Triggered whenever a process calls the openat() syscall
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *event;
    struct task_struct *task;
    const char *file_name = (const char *)ctx->args[1];

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->type = EVENT_OPEN;

    // Get the calling process PID (upper 32 bits of pid_tgid)
    event->open.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();

    event->open.ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(event->open.comm, sizeof(event->open.comm));
    bpf_core_read_user(event->open.file_name, sizeof(event->open.file_name), file_name);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

// kprobe on vfs_write: triggers when the kernel enters vfs_write()
SEC("kprobe/vfs_write")
int trace_vfs_write(struct pt_regs *ctx)
{
    // PT_REGS_PARM1/3 extract the first/third arguments from pt_regs.
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    struct task_struct *task;

    if (!file)
    {
        return 0;
    }

    // Extract node from file struct - file -> dentry -> inode -> mode
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    umode_t mode = BPF_CORE_READ(inode, i_mode);

    // check if the file is a regular file.
    // S_IFMT - bit mask that mask the object type from mode
    // S_IFREG - value that repressent regular file (not sockets, pipes etc)
    if ((mode & S_IFMT) != S_IFREG)
    {
        return 0;
    }

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_WRITE;

    e->write.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    e->write.ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(e->write.comm, sizeof(e->write.comm));

    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    bpf_probe_read_kernel_str(e->write.filename, sizeof(e->write.filename), name);

    e->write.inode = (uint64_t)BPF_CORE_READ(inode, i_ino);
    e->write.dev = (uint64_t)BPF_CORE_READ(inode, i_sb, s_dev);
    e->write.count = count;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";