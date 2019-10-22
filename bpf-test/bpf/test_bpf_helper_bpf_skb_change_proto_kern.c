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

/* The following definition is not included in bpf_helpers.h */

static int (*bpf_skb_change_proto)(void *ctx, __be16 proto, __u64 flags) =
	(void *) BPF_FUNC_skb_change_proto;

/* Convert IPv4 inbound ICMP echo packet to IPv6 where source/destination
 * become configured IPv6 addresses.  We reverse the translation back into
 * IPv4 on egress for the reply.  Note that ICMPv6 != ICMP, so we need to
 * do some work at the ICMP level with types/codes/checksums also.
 */
BPF_HELPER_TEST_FUNC(bpf_skb_change_proto, ipv4toipv6, ingress)
{
	/* We use an icmp hdr for icmp6 because we only want type/code/check */
	struct icmphdr *icmph, icmp6h = { 0 };
	__u32 oldsum = 0, newsum = 0;
	struct ipv6hdr ip6h;
	struct eth_hdr eth;
	__u16 payload_len;
	struct iphdr *iph;
	int ret;

	iph = get_hdr(skb, ETH_P_IP, 0);
	if (!iph)
		return TC_ACT_OK;

	icmph = get_hdr(skb, ETH_P_IP, IPPROTO_ICMP);
	if (!icmph || icmph->type != ICMP_ECHO)
		return TC_ACT_OK;

	/* Copy original ethernet header, as it must be moved. */
	ret = bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));
	if (ret) {
		bpf_debug("bpf_skb_load_bytes returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
                return TC_ACT_OK;
	}
	eth.h_proto = bpf_htons(ETH_P_IPV6);

	/* IPv6 payload len does not include header len. */
	payload_len = bpf_ntohs(iph->tot_len) - (iph->ihl << 2);

	/* Time to construct ICMPv6 header. */
	icmp6h.type = ICMPV6_ECHO_REQUEST;
	icmp6h.code = icmph->code;

	/* Time to construct IPv6 header and copy it. */
	__builtin_memset(&ip6h, 0, sizeof(ip6h));
	ip6h.version = 6;
	ip6h.payload_len = bpf_htons(payload_len);
	ip6h.nexthdr = IPPROTO_ICMPV6;
	ip6h.hop_limit = 8;
	ipv6_addr_set(&ip6h.saddr, BPF_HELPER_IPV6_PREFIX, 0, 0,
		      BPF_HELPER_IPV6_REMOTE_SUFFIX);
	ipv6_addr_set(&ip6h.daddr, BPF_HELPER_IPV6_PREFIX, 0, 0,
		      BPF_HELPER_IPV6_LOCAL_SUFFIX);

	/* Fix up our checksum. Source/destination addresses have changed, and
	 * so has ICMP type.  Note that ICMPv6 also has a pseudo-header, so
	 * we also need to add payload length and ICMPv6 protocol to newsum,
	 * but do not add IPv4 equivalents to oldsum because ICMPv4 does not
	 * use a pseudo-header in checksum calculation.  Only thing that changes
	 * for oldsum is ICMP type.
	 */
	oldsum = icmph->type;
	newsum = sum16((__u16 *)&ip6h.saddr, sizeof(ip6h.saddr) >> 1);
	newsum += sum16((__u16 *)&ip6h.daddr, sizeof(ip6h.daddr) >> 1);
	newsum += icmp6h.type + bpf_htons(payload_len) +
		  bpf_htons(IPPROTO_ICMPV6);

	/* Convert skb to IPv6 and adjust headroom to allow for space for
	 * IPv6 header.
	 */
	ret = bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0);
	if (ret) {
		bpf_debug("bpf_skb_change_proto returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_OK;
	}
	/* Store our copied ethernet header at new start of packet. */
	ret = bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0);
	if (ret) {
		bpf_debug("bpf_skb_store_bytes returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_SHOT;
	}
	/* Store our IPv6 header after the copied ether header */
	ret = bpf_skb_store_bytes(skb, sizeof(eth), &ip6h, sizeof(ip6h), 0);
	if (ret) {
		bpf_debug("bpf_skb_store_bytes returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_SHOT;
	}
	/* Only two bytes type/code change */
	ret = bpf_skb_store_bytes(skb, sizeof(eth) + sizeof(ip6h),
				  &icmp6h, 2, 0);
	if (ret) {
		bpf_debug("bpf_skb_store_bytes returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_SHOT;
	}
	/* Lastly, recompute L4 checksum. */
	ret = bpf_l4_csum_replace(skb, sizeof(eth) + sizeof(ip6h) +
				  offsetof(struct icmphdr, checksum),
				  oldsum, newsum,
				  BPF_F_PSEUDO_HDR | sizeof(newsum));
	if (ret) {
		bpf_debug("bpf_l4_csum_replace returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_SHOT;
	}

	bpf_test_set_status(TEST_PASS);

	return TC_ACT_OK;
}

BPF_HELPER_TEST_FUNC(bpf_skb_change_proto, ipv4toipv6, egress)
{
	/* We use an icmp hdr for icmp6 because we only want type/code/check */
	struct icmphdr *icmp6h, icmph = { 0 };
	__u32 oldsum = 0, newsum = 0;
	struct ipv6hdr *ip6h;
	struct eth_hdr eth;
	__u16 payload_len;
	struct iphdr iph;
	__u32 sum = 0;
	int ret;

	ip6h = get_hdr(skb, ETH_P_IPV6, 0);
	if (!ip6h)
		return TC_ACT_OK;
	payload_len = bpf_ntohs(ip6h->payload_len);

	icmp6h = get_hdr(skb, ETH_P_IPV6, IPPROTO_ICMPV6);
	if (!icmp6h || icmp6h->type != ICMPV6_ECHO_REPLY)
		return TC_ACT_OK;

	/* Copy original ethernet header, as it must be moved. */
	ret = bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));
	if (ret) {
		bpf_debug("bpf_skb_load_bytes returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_OK;
	}
	eth.h_proto = bpf_htons(ETH_P_IP);

	/* Time to construct IPv4 header. */
	__builtin_memset(&iph, 0, sizeof(iph));
	iph.version = 4;
	iph.protocol = IPPROTO_ICMP;
	iph.ihl = sizeof(iph) >> 2;
	iph.tot_len = bpf_htons(payload_len + sizeof(iph));
	iph.saddr = BPF_HELPER_IPV4_LOCAL;
	iph.daddr = BPF_HELPER_IPV4_REMOTE;
	iph.ttl = 255;
	iph.id = (ip6h->flow_lbl[0] << 8) + ip6h->flow_lbl[1];
	iph.frag_off = bpf_htons(IP_DF);
	/* Compute sum for IPv4 checksum below. */
	sum = sum16((__u16 *)&iph, sizeof(iph) >> 1);

	/* Time to construct ICMP header. */
	icmph.type = ICMP_ECHOREPLY;
	icmph.code = icmp6h->code;

	/* Fix up our checksum. Source/destination addresses have changed, and
	 * so has ICMP type.  Note that ICMPv6 also has a pseudo-header, so
	 * we also need to add payload length and ICMPv6 protocol to oldsum,
	 * but do not add IPv4 equivalents to newsum because ICMPv4 does not
	 * use a pseudo-header in checksum calculation, so the only value
	 * that changes for newsum is ICMPv6 type.
	 */
	oldsum = sum16((__u16 *)&ip6h->saddr, sizeof(ip6h->saddr) >> 1);
	oldsum += sum16((__u16 *)&ip6h->daddr, sizeof(ip6h->daddr) >> 1);
	oldsum += icmp6h->type + bpf_htons(payload_len) +
		  bpf_htons(IPPROTO_ICMPV6);
	newsum = icmph.type;
	ret = bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0);
        if (ret) {
                bpf_debug("bpf_skb_change_proto returned %d\n", ret);
                bpf_test_set_status(TEST_FAIL);
                return TC_ACT_OK;
        }
        /* Store our copied ethernet header at new start of packet. */
        ret = bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0);
        if (ret) {
                bpf_debug("bpf_skb_store_bytes returned %d\n", ret);
                bpf_test_set_status(TEST_FAIL);
                return TC_ACT_SHOT;
        }
        /* Store our IP header after the copied ether header */
        ret = bpf_skb_store_bytes(skb, sizeof(eth), &iph, sizeof(iph), 0);
        if (ret) {
                bpf_debug("bpf_skb_store_bytes returned %d\n", ret);
                bpf_test_set_status(TEST_FAIL);
                return TC_ACT_SHOT;
        }
	ret = bpf_l3_csum_replace(skb, sizeof(eth) +
                                  offsetof(struct iphdr, check),
				  0, sum, 0);
	if (ret) {
		bpf_debug("bpf_l3_csum_replace returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_SHOT;
	}

	/* Only two bytes type/code change */
	ret = bpf_skb_store_bytes(skb, sizeof(eth) + sizeof(iph),
				  &icmph, 2, 0);
	if (ret) {
		bpf_debug("bpf_skb_store_bytes returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_SHOT;
	}
        /* Lastly, recompute L4 checksum. */
        ret = bpf_l4_csum_replace(skb, sizeof(eth) + sizeof(iph) +
                                  offsetof(struct icmphdr, checksum),
                                  oldsum, newsum,
                                  BPF_F_PSEUDO_HDR | sizeof(newsum));
        if (ret) {
                bpf_debug("bpf_l4_csum_replace returned %d\n", ret);
                bpf_test_set_status(TEST_FAIL);
                return TC_ACT_SHOT;
        }

	bpf_test_set_status(TEST_PASS);

	return TC_ACT_OK;
}
