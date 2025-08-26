#ifndef COMMON_EVENT_H
#define COMMON_EVENT_H

/**
 * @file common_event.h
 * @brief Shared event definitions between eBPF program and user space.
 *
 * This header defines the event structures that are passed from
 * the kernel eBPF program to user space through the ring buffer.
 *
 * Each event has a type (enum event_type), and a corresponding
 * structure (exec, open, write, fork, exit) that holds metadata
 * for that specific kind of activity.
 *
 * - EVENT_EXEC  : triggered when a process calls execve()
 * - EVENT_OPEN  : triggered when a process calls openat()
 * - EVENT_WRITE : triggered when vfs_write() is invoked
 * - EVENT_FORK  : triggered on sched_process_fork tracepoint
 * - EVENT_EXIT  : triggered on sched_process_exit tracepoint
 *
 * Notes:
 * - TASK_COMM_LEN is the fixed Linux task->comm length (16).
 * - exe_path / file_name / argv buffers are fixed-size - may be truncated if longer than buffer.
 * - union inside `struct event` ensures all event variants fit in the same memory layout for efficient ring buffer transfer.
 *
 * This file is included both by:
 *   1. eBPF program (trace_exec_bpf.c)
 *   2. user space program (trace_exec.c)
 */


#define TASK_COMM_LEN 16
#define MAX_ARGS 5
#define ARG_LEN 128
#define FILE_NAME_LEN 256

enum event_type {
    EVENT_EXEC = 0,
    EVENT_OPEN,
    EVENT_WRITE,
    EVENT_FORK,
    EVENT_EXIT,

    NUM_OF_EVENTS,
};

struct event_fork {
    unsigned int pid;
    unsigned int ppid;
    char comm[TASK_COMM_LEN];
};

struct event_exit {
    unsigned int pid;
    unsigned int ppid;
    char comm[TASK_COMM_LEN];
};

struct event_exec {
    unsigned int pid;
    unsigned int ppid;
    char comm[TASK_COMM_LEN];
    char exe_path[FILE_NAME_LEN];
    char argv[MAX_ARGS][ARG_LEN];
};

struct event_open {
    unsigned int pid;
    unsigned int ppid;
    char comm[TASK_COMM_LEN];
    char file_name[FILE_NAME_LEN];
};

struct event_write {
    unsigned int pid;
    unsigned int ppid;
    char comm[TASK_COMM_LEN];
    uint64_t count;
    uint64_t dev;
    uint64_t inode;
    char filename[FILE_NAME_LEN];
};

struct event {
    enum event_type type;
    union {
        struct event_exec exec;
        struct event_open open;
        struct event_write write;
        struct event_fork fork;
        struct event_exit exit;
    };
};

#endif // COMMON_EVENT_H
