
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include <stdbool.h>
#include "trace_exec.skel.h"
#include "common_event.h"


/*
 * Tracer User-space side:
 * - Loads and attaches the eBPF program generated from trace_exec_bpf.c
 * - Consumes events from a ring buffer map and print it to the console
 */

/* Use sig_atomic_t to make the exiting flag safe to modify from a signal handler */
static volatile sig_atomic_t exiting = 0;

static const char *FMT_EXEC ="[EXEC] PID: %u\tPPID: %u\tCOMM: %s\tEXE_PATH: %s";
static const char *FMT_FORK = "[FORK] PID: %u\tPPID: %u\tCOMM: %s\n";
static const char *FMT_OPEN = "[OPENAT] PID: %u\tPPID: %u\tCOMM: %s\tFILE: %s\n";
static const char *FMT_WRITE = "[WRITE] PID: %u\tPPID: %u\tCOMM: %s\tFILE: %s\tCOUNT: %lu\n";
static const char *FMT_EXIT = "[EXIT] PID: %u\tPPID: %u\tCOMM: %s\n";
static const char *TXT_UNKNOWN = "[UNKNOWN EVENT]\n";
static const char *FMT_WARN_EVENT_TOO_SMALL = "[WARN] event too small: %zu < %zu\n";
static const char *FMT_ERROR_LOAD_SKELETON = "Failed to open and load BPF skeleton\n";
static const char *FMT_ERROR_ATTACH_SKELETON = "Failed to attach BPF skeleton: %d\n";
static const char *FMT_ERROR_CREATE_RING_BUFFER = "Failed to create ring buffer\n";

/* Helper to print argv[] captured by the eBPF execve program */
static void print_argv(const char argv[][ARG_LEN], int max_args)
{
    printf("ARGV:");
    for (int i = 0; i < max_args; ++i)
    {
        if (argv[i][0] == '\0')
            break;
        printf(" %s", argv[i]);
    }
    printf("\n");
}

/* --- Per-event handlers --- */
static int handle_exec(const struct event *event)
{
    printf(FMT_EXEC, event->exec.pid, event->exec.ppid, event->exec.comm, event->exec.exe_path);
    print_argv(event->exec.argv, MAX_ARGS);
    return 0;
}

static int handle_fork(const struct event *event)
{
    printf(FMT_FORK, event->fork.pid, event->fork.ppid, event->fork.comm);
    return 0;
}

static int handle_open(const struct event *event)
{
    printf(FMT_OPEN, event->open.pid, event->open.ppid, event->open.comm, event->open.file_name);
    return 0;
}

static int handle_write(const struct event *event)
{
    printf(FMT_WRITE,
           event->write.pid, event->write.ppid, event->write.comm,
           event->write.filename, (unsigned long)event->write.count);
    return 0;
}

static int handle_exit(const struct event *event)
{
    printf(FMT_EXIT, event->exit.pid, event->exit.ppid, event->exit.comm);
    return 0;
}

static int handle_unknown(const struct event *event)
{
    (void)event;
    printf("%s", TXT_UNKNOWN);
    return 0;
}

/* --- Lookup table: maps event_type -> handler function ------------------ */

typedef int (*event_handler_fn)(const struct event *event);

static event_handler_fn g_handlers[NUM_OF_EVENTS] = {
    [EVENT_EXEC] = handle_exec,
    [EVENT_FORK] = handle_fork,
    [EVENT_OPEN] = handle_open,
    [EVENT_WRITE] = handle_write,
    [EVENT_EXIT] = handle_exit,
};

/* Callback that invoked by libbpf on each event is write to the ring buffer */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;

    //check the size is enough to contain struct event size 
    if (data_sz < sizeof(struct event))
    {
        fprintf(stderr, FMT_WARN_EVENT_TOO_SMALL, data_sz, sizeof(struct event));
        return -1;
    }

    const struct event *event = (const struct event *)data;

    if (event->type < 0 || event->type >= NUM_OF_EVENTS)
    {
        return handle_unknown(event);
    }

    event_handler_fn event_handler_function = g_handlers[event->type];
    if (!event_handler_function)
    {
        return handle_unknown(event);
    }

    return event_handler_function(event);
}

static void handle_signal(int sig)
{
    (void)sig;
    exiting = 1;
}

int main()
{
    struct trace_exec_bpf *skeleton = NULL;
    struct ring_buffer *ring_buffer = NULL;
    int attach_exit_status = 0;

    // Register signal handler
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Load and verify BPF program
    skeleton = trace_exec_bpf__open_and_load();
    if (!skeleton)
    {
        fprintf(stderr, "%s", FMT_ERROR_LOAD_SKELETON);
        return 1;
    }

    // Attach tracepoint
    attach_exit_status = trace_exec_bpf__attach(skeleton);
    if (attach_exit_status)
    {
        fprintf(stderr, FMT_ERROR_ATTACH_SKELETON, attach_exit_status);
        trace_exec_bpf__destroy(skeleton);
        return 1;
    }

    // Set up ring buffer
    ring_buffer = ring_buffer__new(bpf_map__fd(skeleton->maps.events), handle_event, NULL, NULL);
    if (!ring_buffer)
    {
        fprintf(stderr, "%s", FMT_ERROR_CREATE_RING_BUFFER);
        trace_exec_bpf__detach(skeleton);
        trace_exec_bpf__destroy(skeleton);
        return 1;
    }

    while (!exiting)
    {
        //Wait for events from the kernel
        // timeout is set for 200 millisecond, so the program could check exiting flag and not stuck until event is arrived.
        int n = ring_buffer__poll(ring_buffer, 200);

        if (n < 0)
        {
            fprintf(stderr, "[ERROR] ring_buffer__poll failed: %d\n", n);
            break;
        }
    }

    // Cleanup
    ring_buffer__free(ring_buffer);
    trace_exec_bpf__detach(skeleton);
    trace_exec_bpf__destroy(skeleton);

    return 0;
}
