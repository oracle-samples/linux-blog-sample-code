// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022, Oracle and/or its affiliates.

#include "vmlinux.h"

#include <bpf/usdt.bpf.h>

int got_nargs = 0;

char _license[] SEC("license") = "GPL";

SEC("usdt//proc/self/exe:example:args")
int BPF_USDT(args, int nargs)
{
	got_nargs = nargs;

	return 0;
}
