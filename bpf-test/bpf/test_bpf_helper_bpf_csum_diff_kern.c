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

/* Note checksum, zero it and calculate it from scratch using
 * bpf_csum_diff().  Replace with updated checksum and ensure it matches
 * original.
 */
BPF_HELPER_TEST_FUNC(bpf_csum_diff, create, ingress)
{
	struct iphdr *iph;
	__sum16 old, new;
	__u32 csum = 0;
	int ret;

	iph = get_hdr(skb, ETH_P_IP, 0);
	if (!iph)
		return TC_ACT_OK;
	if (!get_hdr(skb, ETH_P_IP, IPPROTO_ICMP))
		return TC_ACT_OK;

	old = iph->check;
	iph->check = 0;
	csum = bpf_csum_diff(NULL, 0, iph, sizeof(*iph), 0);

	ret = bpf_l3_csum_replace(skb, sizeof(struct eth_hdr) +
				  offsetof(struct iphdr, check),
				  0, csum, sizeof(csum));
	if (ret) {
		bpf_debug("bpf_l3_csum_replace returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_OK;
	}
	/* csum_replace invalidates iph, get it again. */
	iph = get_hdr(skb, ETH_P_IP, 0);
	if (!iph)
		return TC_ACT_OK;
	new = iph->check;
	if (new != old) {
		bpf_debug("bpf_csum diff returned %x, expected %x\n",
			  new, old);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_OK;
	}

	bpf_test_set_status(TEST_PASS);

	return TC_ACT_OK;
}

BPF_HELPER_TEST_FUNC(bpf_csum_diff, create, egress)
{
	/* Nothing to do here. */
	return TC_ACT_OK;
}

/* Add/subtract 0x100 from source/destination IP on ingress/egress, and
 * use bpf_csum_diff() to compute the checksum difference.  Use
 * bpf_l3_csum_replace() to update the checksum based on the difference.
 * We have configured local/remote IP addresses +/-0x100 to the original
 * source and destination, so ping should be valid and be responded to.
 */
static __always_inline int add_csum_helper(struct __sk_buff *skb, int add)
{
	__be32 oldaddr, newaddr;
	struct iphdr *iph;
	__sum16 old;
	__be32 addval;
	__u32 csum;
	int ret;

	addval = add ? bpf_htonl(0x100) : -bpf_htonl(0x100);

	iph = get_hdr(skb, ETH_P_IP, 0);
	if (!iph)
		return TC_ACT_OK;
	if (!get_hdr(skb, ETH_P_IP, IPPROTO_ICMP))
		return TC_ACT_OK;

	old = iph->check;
	/* Modify IP source, dest */
	oldaddr = iph->saddr;
	newaddr = oldaddr + addval;
	iph->saddr = newaddr;
	csum = bpf_csum_diff(&oldaddr, sizeof(oldaddr),
			    &newaddr, sizeof(newaddr), old);
	oldaddr = iph->daddr;
	newaddr = oldaddr + addval;
	iph->daddr = newaddr;
	csum = bpf_csum_diff(&oldaddr, sizeof(oldaddr),
			     &newaddr, sizeof(newaddr), csum);
	ret = bpf_l3_csum_replace(skb, sizeof(struct eth_hdr) +
				  offsetof(struct iphdr, check),
				  old, csum, sizeof(csum));
	if (ret) {
		bpf_debug("bpf_l3_csum_replace returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_OK;
	}
	return TC_ACT_OK;
}

BPF_HELPER_TEST_FUNC(bpf_csum_diff, add, ingress)
{
	return add_csum_helper(skb, 1);
}

BPF_HELPER_TEST_FUNC(bpf_csum_diff, add, egress)
{
	int ret;

	ret = add_csum_helper(skb, 0);
	bpf_test_set_status(ret ? TEST_FAIL : TEST_PASS);

	return TC_ACT_OK;
}

#define	ICMP_REMOVE_OFFSET	56
#define	ICMP_REMOVE_LEN		8

/* Checksum calculation when pulling data.  We zero 8 bytes of ICMP
 * data, recalculate ICMP checksum.  Easier then altering length which
 * has knock-on effects for IP header (tot len).
 */
BPF_HELPER_TEST_FUNC(bpf_csum_diff, remove, ingress)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	__u8 removedata_copy[ICMP_REMOVE_LEN];
	struct icmphdr *icmph;
	struct iphdr *iph;
	__u32 csum = 0;
	__u16 offset;
	__sum16 old;
	int ret;

	iph = get_hdr(skb, ETH_P_IP, 0);
	if (!iph)
		return TC_ACT_OK;
	icmph = get_hdr(skb, ETH_P_IP, IPPROTO_ICMP);
	if (!icmph)
		return TC_ACT_OK;

	old = icmph->checksum;
	offset = sizeof(struct eth_hdr) + sizeof(struct iphdr) +
		 ICMP_REMOVE_OFFSET;
	if (data + offset + ICMP_REMOVE_LEN > data_end)
		return TC_ACT_OK;

	ret = bpf_skb_load_bytes(skb, offset, &removedata_copy,
				 sizeof(removedata_copy));
	csum = bpf_csum_diff(removedata_copy, ICMP_REMOVE_LEN, NULL, 0, old);
	__builtin_memset(data + offset, 0, ICMP_REMOVE_LEN);

	if (data + sizeof(struct eth_hdr) + sizeof(struct iphdr) +
	    offsetof(struct icmphdr, checksum) > data_end)
		return TC_ACT_OK;
	ret = bpf_l4_csum_replace(skb, sizeof(struct eth_hdr) +
				  sizeof(struct iphdr) +
				  offsetof(struct icmphdr, checksum),
				  old, csum, sizeof(csum));
	if (ret) {
		bpf_debug("bpf_l4_csum_replace returned %d\n", ret);
		bpf_test_set_status(TEST_FAIL);
		return TC_ACT_OK;
	}
	return TC_ACT_OK;
}

BPF_HELPER_TEST_FUNC(bpf_csum_diff, remove, egress)
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
