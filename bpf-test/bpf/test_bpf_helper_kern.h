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

#define KBUILD_MODNAME "foo"

#include <uapi/linux/types.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/filter.h>
#include <linux/pkt_cls.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

#include "test_bpf_helper.h"

#define BPF_HELPER_TEST_FUNC(helper, name, direction)			\
SEC(BPF_HELPER_TEST_NAME(helper, name, direction))			\
static __always_inline int helper##_##name##_##direction(struct __sk_buff *skb)

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define PIN_GLOBAL_NS           2

struct bpf_elf_map {
        __u32 type;
        __u32 size_key;
        __u32 size_value;
        __u32 max_elem;
        __u32 flags;
        __u32 id;
        __u32 pinning;
};

/* test status; key is test id; value status. */
struct bpf_elf_map SEC("maps") bpf_helper_test_map = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(long),
	.size_value = sizeof(long),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 256,
};

/* copy of 'struct ethhdr' without __packed */
struct eth_hdr {
        unsigned char   h_dest[ETH_ALEN];
        unsigned char   h_source[ETH_ALEN];
        unsigned short  h_proto;
};

/* Don't fragment flag */
#define	IP_DF			0x4000

#ifdef BPFDEBUG
#define	bpf_debug(debugmsg, ...) \
	do { \
                char m[] = debugmsg; \
                bpf_trace_printk(m, sizeof(m), ## __VA_ARGS__); \
        } while(0)
#else
#define bpf_debug(debugmsg, ...) \
                do { } while (0)
#endif

/* Target/local addresses are ::11/::22 */
#define	TARGET_IPV6_ADDR	bpf_htonl(0x11)
#define	LOCAL_IPV6_ADDR		bpf_htonl(0x22)

/* Target/local addresses are 10.1.1.100/10.1.1.200 */
#define	TARGET_IPV4_ADDR	bpf_htonl(0x0a010164)
#define	LOCAL_IPV4_ADDR		bpf_htonl(0x0a0101c8)

static __always_inline long bpf_test_current(void)
{
	long i, test, *status;
#pragma clang loop unroll(full)
	for (i = 0; i < ARRAY_SIZE(bpf_helper_tests); i++) {
		test = i;
		status = bpf_map_lookup_elem(&bpf_helper_test_map, &test);
		if (status && *status == TEST_NOT_RUN)
			return test;
	}
	return -1;
}
		
static __always_inline void bpf_test_set_status(long status)
{
	long test = bpf_test_current();

	if (test < 0)
		return;

	if (status == TEST_PASS)
		bpf_debug("Test %ld passed.\n", test);
	else
		bpf_debug("Test %ld failed.\n", test);

	bpf_map_update_elem(&bpf_helper_test_map, &test, &status,
			    BPF_ANY);
}

static __always_inline void *get_hdr(struct __sk_buff *skb,
				     __u16 l3_proto, __u8 l4_proto)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct eth_hdr *eth = data;
	struct ipv6hdr *ipv6hdr;
	struct iphdr *iphdr;
	__u8 l4_hdrproto;
	__u16 l3_hdrlen;

	if (data + sizeof(*eth) > data_end)
		return NULL;

	if (bpf_ntohs(eth->h_proto) != l3_proto)
		return NULL;

	switch (l3_proto) {
	case ETH_P_IP:
		if (data + sizeof(*eth) + sizeof(struct iphdr) > data_end)
			return NULL;
		iphdr = data + sizeof(*eth);
		l3_hdrlen = iphdr->ihl << 2;
		l4_hdrproto = iphdr->protocol;
		if (data + sizeof(*eth) + l3_hdrlen > data_end)
			return NULL;
		break;
	case ETH_P_IPV6:
		if (data + sizeof(*eth) + sizeof(struct ipv6hdr) > data_end)
			return NULL;
		ipv6hdr = data + sizeof(*eth);
		l3_hdrlen = sizeof(struct ipv6hdr);
		l4_hdrproto = ipv6hdr->nexthdr;
		break;
	default:
		return NULL;
	}

	if (!l4_proto)
		return data + sizeof(*eth);

	if (l4_proto != l4_hdrproto)
		return NULL;

	switch (l4_proto) {
	case IPPROTO_ICMP:
		if (data + sizeof(*eth) + l3_hdrlen + sizeof(struct icmphdr) >
		    data_end)
			return NULL;
		break;
	case IPPROTO_ICMPV6:
		if (data + sizeof(*eth) + l3_hdrlen + sizeof(struct icmphdr) >
		    data_end)
			return NULL;
		break;
	default:
		return NULL; 
	}
	return data + sizeof(*eth) + l3_hdrlen;
}

static __always_inline void ipv6_addr_set(struct in6_addr *addr,
					  __be32 w1, __be32 w2,
					  __be32 w3, __be32 w4)
{
	addr->in6_u.u6_addr32[0] = w1;
	addr->in6_u.u6_addr32[1] = w2;
	addr->in6_u.u6_addr32[2] = w3;
	addr->in6_u.u6_addr32[3] = w4;
}

static __always_inline __u32 sum16(__u16 *addr, __u8 len)
{
	__u32 sum = 0;
	int i;

#pragma clang loop unroll(full)
	for (i = 0; i < len; i++)
		sum += *addr++;

	return sum;
}

char _license[] SEC("license") = "GPL";
