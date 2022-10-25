// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022, Oracle and/or its affiliates.

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

SEC("kprobe/do_sysinfo")
int BPF_PROG(do_sysinfo, struct sysinfo *sysinfo)
{
	__bpf_printk("called do_sysinfo\n");
	return 0;
}
