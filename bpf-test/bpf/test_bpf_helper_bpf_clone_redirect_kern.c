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

struct icmphdr_type_code {
	__u8	type;
	__u8	code;
};

/* Test ingress redirect; change ICMP code to bogus value (1) and do clone
 * redirect.  Next time we find this code, change it back (otherwise checksum
 * validation will fail etc).  Drop original packet.
 */
BPF_HELPER_TEST_FUNC(bpf_clone_redirect, in, ingress)
{
	struct icmphdr *icmph;
	struct iphdr *iph;
	int ret = 0;

	iph = get_hdr(skb, ETH_P_IP, 0);
	if (!iph)
		return TC_ACT_OK;
	icmph = get_hdr(skb, ETH_P_IP, IPPROTO_ICMP);
	if (!icmph)
		return TC_ACT_OK;

	switch (icmph->code) {
	case 0:
		icmph->code = 1;
		ret = bpf_clone_redirect(skb, skb->ifindex, BPF_F_INGRESS);
		if (ret != 0) {
			bpf_debug("bpf_clone_redirect returned %d\n", ret);
			bpf_test_set_status(TEST_FAIL);
		}
		return TC_ACT_SHOT;
	case 1:
		icmph->code = 0;
		bpf_test_set_status(TEST_PASS);
		return TC_ACT_OK;
	default:
		bpf_debug("Unexpected icmp code %d\n", icmph->code);
		return TC_ACT_OK;
	}
}

BPF_HELPER_TEST_FUNC(bpf_clone_redirect, in, egress)
{
	/* Nothing to do here. */
	return TC_ACT_OK;
}

/* Swap source, destination ethernet/IP addresses, make ICMP echo request
 * an echo reply and update ICMP checksum.  IP checksum stays the same
 * since we just swap src/dst.  Use clone_redirect to redirect out and
 * drop original packet.
 */
BPF_HELPER_TEST_FUNC(bpf_clone_redirect, out, ingress)
{
	struct icmphdr_type_code tcnew = { ICMP_ECHOREPLY, 0 };
	struct icmphdr_type_code tcold = { ICMP_ECHO, 0 };
	struct eth_hdr eth_copy;
	struct icmphdr *icmph;
	__be32 saddr, daddr;
	struct iphdr *iph;
	__u32 diff = 0;
	int ret;

	iph = get_hdr(skb, ETH_P_IP, 0);
	if (!iph)
		return TC_ACT_OK;
	icmph = get_hdr(skb, ETH_P_IP, IPPROTO_ICMP);
	if (!icmph)
		return TC_ACT_OK;

	ret = bpf_skb_load_bytes(skb, offsetof(struct eth_hdr, h_source),
				 &eth_copy.h_dest, sizeof(eth_copy.h_dest));
	if (ret) {
		bpf_debug("bpf_skb_load_bytes returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_OK;
	}
	ret = bpf_skb_load_bytes(skb, offsetof(struct eth_hdr, h_dest),
				 &eth_copy.h_source, sizeof(eth_copy.h_source));
	if (ret) {
		bpf_debug("bpf_skb_load_bytes returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_OK;
	}
	eth_copy.h_proto = bpf_htons(ETH_P_IP);
	ret = bpf_skb_store_bytes(skb, 0, &eth_copy, sizeof(eth_copy), 0);
	if (ret) {
		bpf_debug("bpf_skb_store_bytes returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_OK;
	}
	/* bpf_skb_store_bytes invalidates pointers, get iph/icmph again. */
	iph = get_hdr(skb, ETH_P_IP, 0);
	if (!iph)
		return TC_ACT_SHOT;
	icmph = get_hdr(skb, ETH_P_IP, IPPROTO_ICMP);
	if (!icmph)
		return TC_ACT_SHOT;

	saddr = iph->daddr;
	daddr = iph->saddr;
	iph->saddr = saddr;
	iph->daddr = daddr;

	icmph->type = ICMP_ECHOREPLY;

	diff = bpf_csum_diff(&tcold, sizeof(tcold), &tcnew, sizeof(tcnew), 0);

	ret = bpf_l4_csum_replace(skb, sizeof(struct eth_hdr) + sizeof(*iph) +
				  offsetof(struct icmphdr, checksum),
				  0, diff, 0);
	if (ret) {
		bpf_debug("bpf_l4_csum_replace returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_OK;
	}
	ret = bpf_clone_redirect(skb, skb->ifindex, 0);
	if (ret != 0) {
		bpf_debug("bpf_clone_redirect returned %d\n", ret);
		return TC_ACT_SHOT;
	}
	/* drop original packet. */
	return TC_ACT_SHOT;
}

BPF_HELPER_TEST_FUNC(bpf_redirect, out, egress)
{
	/* Nothing to do here. */
	return TC_ACT_OK;
}
