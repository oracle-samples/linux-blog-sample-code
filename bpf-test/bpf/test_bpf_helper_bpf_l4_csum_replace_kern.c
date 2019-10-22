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

/* Ensure we're modifying ICMP data not header fields. */
#define	ICMP_MODIFY_OFFSET	32

/* Checksum calculation when changing data.  We change 2/4 bytes of ICMP
 * data, recalculate ICMP checksum.
 */
static __always_inline int l4_csum_replace_ingress(struct __sk_buff *skb,
						   int by_field,
						   __u8 size)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	__u32 old = 0, new = 0;
	struct icmphdr *icmph;
	struct iphdr *iph;
	__u16 offset;
	s64 diff;
	int ret;

	if (size > 4)
		return TC_ACT_OK;
	iph = get_hdr(skb, ETH_P_IP, 0);
	if (!iph)
		return TC_ACT_OK;
	icmph = get_hdr(skb, ETH_P_IP, IPPROTO_ICMP);
	if (!icmph)
		return TC_ACT_OK;

	offset = sizeof(struct eth_hdr) + sizeof(struct iphdr) +
		 ICMP_MODIFY_OFFSET;
	if (data + offset + size > data_end)
		return TC_ACT_OK;

	ret = bpf_skb_load_bytes(skb, offset, &old, size);
	if (ret) {
		bpf_debug("bpf_skb_load_bytes returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_OK;
        }
	new = ~old;
	ret = bpf_skb_store_bytes(skb, offset, &new, size, 0);
	if (ret) {
		bpf_debug("bpf_skb_store_bytes returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
	}
	if (data + sizeof(struct eth_hdr) + sizeof(struct iphdr) +
	    offsetof(struct icmphdr, checksum) > data_end)
		return TC_ACT_OK;
	if (by_field) {
		ret = bpf_l4_csum_replace(skb, sizeof(struct eth_hdr) +
					  sizeof(struct iphdr) +
					  offsetof(struct icmphdr, checksum),
					  old, new, size);
	} else {
		diff = bpf_csum_diff(&old, size, &new, size, 0);
		ret = bpf_l4_csum_replace(skb, sizeof(struct eth_hdr) +
					  sizeof(struct iphdr) +
					  offsetof(struct icmphdr, checksum),
					  0, diff, 0);
	}
	if (ret) {
		bpf_debug("bpf_l4_csum_replace returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_OK;
	}
	return TC_ACT_OK;
}

BPF_HELPER_TEST_FUNC(bpf_l4_csum_replace, by_field2, ingress)
{
	return l4_csum_replace_ingress(skb, 1, 2);
}

static __always_inline int l4_csum_replace_egress(struct __sk_buff *skb)
{
	struct icmphdr *icmph;
	struct iphdr *iph;

	iph = get_hdr(skb, ETH_P_IP, 0);
        if (!iph)
                return TC_ACT_OK;
        icmph = get_hdr(skb, ETH_P_IP, IPPROTO_ICMP);
        if (!icmph)
                return TC_ACT_OK;

	bpf_test_set_status(TEST_PASS);
	return TC_ACT_OK;
}

BPF_HELPER_TEST_FUNC(bpf_l4_csum_replace, by_field2, egress)
{
	return l4_csum_replace_egress(skb);
}

BPF_HELPER_TEST_FUNC(bpf_l4_csum_replace, by_field4, ingress)
{
	return l4_csum_replace_ingress(skb, 1, 4);
}

BPF_HELPER_TEST_FUNC(bpf_l4_csum_replace, by_field4, egress)
{
	return l4_csum_replace_egress(skb);
}

BPF_HELPER_TEST_FUNC(bpf_l4_csum_replace, by_diff, ingress)
{
        return l4_csum_replace_ingress(skb, 0, 4);
}

BPF_HELPER_TEST_FUNC(bpf_l4_csum_replace, by_diff, egress)
{
        return l4_csum_replace_egress(skb);
}
