#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "iolatency.h"

histogram empty_histogram;

int main(int argc, char *argv[])
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link[2];
    int prog_fd;
    u_int32_t zero = 0;

    // Parse cli arguments
    if (argc != 2)
    {
        fprintf(stderr, "usage: %s <interval>\n", argv[0]);
        return 1;
    }
    int interval = atoi(argv[1]);

    // Load and verify BPF application
    fprintf(stderr, "Loading BPF code in memory\n");
    obj = bpf_object__open_file("iolatency.bpf.o", NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    // Load BPF program
    fprintf(stderr, "Loading and verifying the code in the kernel\n");
    if (bpf_object__load(obj))
    {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    // Initialize histogram map
    struct bpf_map *map;
    map = bpf_object__find_map_by_name(obj, "histogram_map");
    if (libbpf_get_error(map))
    {
        fprintf(stderr, "ERROR: finding BPF map failed\n");
        return 1;
    }
    int map_fd = bpf_map__fd(map);
    if (bpf_map_update_elem(map_fd, &zero, &empty_histogram, BPF_ANY) < 0)
    {
        fprintf(stderr, "ERROR: initializing histogram eBPF array map failed\n");
        return 1;
    }

    // Attach BPF program: block_rq_insert
    fprintf(stderr, "Attaching BPF program to tracepoint\n");
    prog = bpf_object__find_program_by_name(obj, "handle_tracepoint_block_rq_issue");
    if (libbpf_get_error(prog))
    {
        fprintf(stderr, "ERROR: finding BPF program failed\n");
        return 1;
    }
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0)
    {
        fprintf(stderr, "ERROR: getting BPF program FD failed\n");
        return 1;
    }
    // Check it out at: /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter
    link[0] = bpf_program__attach_raw_tracepoint(prog, "block_rq_issue");
    if (libbpf_get_error(link[0]))
    {
        fprintf(stderr, "ERROR: Attaching BPF program to tracepoint failed\n");
        return 1;
    }

    // Attach BPF program: block_rq_complete
    fprintf(stderr, "Attaching BPF program to tracepoint\n");
    prog = bpf_object__find_program_by_name(obj, "handle_tracepoint_block_rq_complete");
    if (libbpf_get_error(prog))
    {
        fprintf(stderr, "ERROR: finding BPF program failed\n");
        return 1;
    }
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0)
    {
        fprintf(stderr, "ERROR: getting BPF program FD failed\n");
        return 1;
    }
    // Check it out at: /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter
    link[1] = bpf_program__attach_raw_tracepoint(prog, "block_rq_complete");
    if (libbpf_get_error(link[1]))
    {
        fprintf(stderr, "ERROR: Attaching BPF program to tracepoint failed\n");
        return 1;
    }

    // Print histogram every interval
    while (1)
    {
        sleep(interval);

        // Get histogram
        histogram histogram;
        if (bpf_map_lookup_elem(map_fd, &zero, &histogram) < 0)
        {
            fprintf(stderr, "ERROR: Map histogram lookup failed\n");
            break;
        }

        // Print histogram
        print_histogram(histogram);

        // Clear histogram
        if (bpf_map_update_elem(map_fd, &zero, &empty_histogram, BPF_ANY) < 0)
        {
            fprintf(stderr, "ERROR: clearing histogram eBPF array map failed\n");
            return 1;
        }
    }

    // Cleanup
    bpf_link__destroy(link[0]);
    bpf_link__destroy(link[1]);
    bpf_object__close(obj);

    return 0;
}
uint64_t histogram_max(histogram h)
{
    uint64_t res = 0;
    for (int i = 0; i < HISTOGRAM_NCOLUMN + 1; i++)
    {
        if (res < h[i])
        {
            res = h[i];
        }
    }
    return res;
}

void print_histogram(histogram h)
{
    uint64_t max = histogram_max(h);
    printf("     usecs      : count       distribution\n");
    for (int i = 0; i < HISTOGRAM_NCOLUMN; i++)
    {
        uint64_t l = i ? (1 << i) : 0;
        uint64_t r = (1 << (i + 1)) - 1;
        printf("%5lu -> %-7lu: %-10lu |", l, r, h[i]);

        uint64_t n_asterisk = max == 0 ? 0 : ((float)h[i] / max) * HISTOGRAM_HEIGHT;
        for (int j = 0; j < HISTOGRAM_HEIGHT; j++)
        {
            if (n_asterisk > j)
            {
                printf("*");
            }
            else
            {
                printf(" ");
            }
        }

        printf("|\n");
    }
}