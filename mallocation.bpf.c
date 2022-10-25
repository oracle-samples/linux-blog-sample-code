// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022, Oracle and/or its affiliates. */

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value, int);
} alloc_map SEC(".maps");

SEC("uprobe/libc.so.6:malloc")
int malloc_counter(struct pt_regs *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;
	int *szp, sz = 0;

	szp = bpf_map_lookup_elem(&alloc_map, &pid);
	if (szp)
		sz += *szp;
	sz += PT_REGS_PARM1_CORE(ctx);
	bpf_map_update_elem(&alloc_map, &pid, &sz, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
