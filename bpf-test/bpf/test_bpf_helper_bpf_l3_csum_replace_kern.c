/*
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include "test_bpf_helper_kern.h"

/* Add/subtract 0x100 from source/destination IP on ingress/egress, and
 * use bpf_l3_csum_replace() to compute the checksum difference.  If
 * by_field is true, use multiple calls to csum_replace to update
 * checksum.  If it is 0, we use a single call with the difference in the
 * sum of changed values to update the checksum.
 */
static __always_inline int diff_csum_helper(struct __sk_buff *skb, int add,
					    int by_field)
{
        __be32 oldaddr, newaddr;
	struct iphdr *iph;
	__be32 addval;
	int ret;

	addval = add ? bpf_htonl(0x100) : -bpf_htonl(0x100);

	iph = get_hdr(skb, ETH_P_IP, 0);
        if (!iph)
                return TC_ACT_OK;
        if (!get_hdr(skb, ETH_P_IP, IPPROTO_ICMP))
                return TC_ACT_OK;

        /* Modify IP source, dest */
        oldaddr = iph->saddr;
        newaddr = oldaddr + addval;
        iph->saddr = newaddr;
	if (by_field) {
		ret = bpf_l3_csum_replace(skb, sizeof(struct eth_hdr) +
					  offsetof(struct iphdr, check),
					  oldaddr, newaddr, sizeof(oldaddr));
		if (ret) {
			bpf_debug("bpf_l3_csum_replace returned %d\n", ret);
			bpf_test_set_status(TEST_FAIL);
			return TC_ACT_OK;
		}
        	/* csum_replace invalidates iph, get it again. */
		iph = get_hdr(skb, ETH_P_IP, 0);
		if (!iph)
			return TC_ACT_OK;
	}
	oldaddr = iph->daddr;
	newaddr = oldaddr + addval;
	iph->daddr = newaddr;
	if (by_field) {
		ret = bpf_l3_csum_replace(skb, sizeof(struct eth_hdr) +
					  offsetof(struct iphdr, check),
					  oldaddr, newaddr, sizeof(oldaddr));
	} else {
		ret = bpf_l3_csum_replace(skb, sizeof(struct eth_hdr) +
					  offsetof(struct iphdr, check),
					  0, addval + addval, 0);
	}
	if (ret) {
		bpf_debug("bpf_l3_csum_replace returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_OK;
	}

	return TC_ACT_OK;
}

BPF_HELPER_TEST_FUNC(bpf_l3_csum_replace, by_field, ingress)
{
	return diff_csum_helper(skb, 1, 1);
}

BPF_HELPER_TEST_FUNC(bpf_l3_csum_replace, by_field, egress)
{
	int ret = diff_csum_helper(skb, 0, 1);

	if (!ret)
		bpf_test_set_status(TEST_PASS);
	return TC_ACT_OK;
}

BPF_HELPER_TEST_FUNC(bpf_l3_csum_replace, by_sum, ingress)
{
	return diff_csum_helper(skb, 1, 0);
}

BPF_HELPER_TEST_FUNC(bpf_l3_csum_replace, by_sum, egress)
{
	int ret = diff_csum_helper(skb, 0, 1);

	if (!ret)
		bpf_test_set_status(TEST_PASS);
	return TC_ACT_OK;
}
