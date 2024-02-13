// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
/* Adapted by yanniszark in 2024 */

// All linux kernel type definitions are in vmlinux.h
#include "vmlinux.h"
// BPF helpers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "iolatency.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY); // map type
    __type(key, u32);                 // key type
    __type(value, histogram);         // value type
    __uint(max_entries, 1);           // number of entries
} histogram_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH); // map type
    __type(key, struct request *);   // key type
    __type(value, u64);              // value type
    __uint(max_entries, 10000);      // number of entries
} req_insert_ns_map SEC(".maps");

// SEC name is important! libbpf infers program type from it.
// See: https://docs.kernel.org/bpf/libbpf/program_types.html#program-types-and-elf
SEC("raw_tracepoint/block_rq_issue")
int BPF_PROG(handle_tracepoint_block_rq_issue, struct request *req)
{
    // Store current time in hashmap
    u64 now_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&req_insert_ns_map, &req, &now_ns, BPF_ANY);
    return 0;
}

inline size_t calc_column(u64 n)
{
    size_t i;
    for (i = 0; i < HISTOGRAM_NCOLUMN; i++)
    {
        if (n < (1 << (i + 1)))
        {
            return i;
        }
    }

    // Histogram has an extra column for anything beyond
    return i;
}

// SEC name is important! libbpf infers program type from it.
// See: https://docs.kernel.org/bpf/libbpf/program_types.html#program-types-and-elf
SEC("raw_tracepoint/block_rq_complete")
int BPF_PROG(handle_tracepoint_block_rq_complete, struct request *req, int error, unsigned int nr_bytes)
{
    // Get request's insert time
    u64 *req_insert_ns = bpf_map_lookup_elem(&req_insert_ns_map, &req);
    if (!req_insert_ns)
    {
        // Skip; request was not registered when inserted
        return 0;
    }

    // Get histogram map
    // histogram is stored as a singleton array
    u32 zero = 0;
    histogram *h = bpf_map_lookup_elem(&histogram_map, &zero);
    if (!h)
    {
        // Skip: histogram has not been initialized yet
        return 0;
    }

    // Calculate delta
    u64 now_ns = bpf_ktime_get_ns();
    if (now_ns < *req_insert_ns)
    {
        // Skip; somehow request completes before insertion?
        return 0;
    }
    u64 delta = (now_ns - *req_insert_ns) / 1000;

    // Calculate which column
    size_t column = calc_column(delta);

    // Update histogram
    __sync_fetch_and_add(&(*h)[column], 1);

    return 0;
}