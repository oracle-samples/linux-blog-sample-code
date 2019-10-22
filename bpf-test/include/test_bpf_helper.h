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

#ifndef bpf_htonl
#define	bpf_htonl(x) htonl(x)
#endif
#ifndef bpf_ntohl
#define	bpf_ntohl(x) ntohl(x)
#endif

#ifndef ETH_ALEN
#define	ETH_ALEN 6
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

typedef enum {
	TEST_NOT_RUN = 0,
	TEST_PASS,
	TEST_FAIL
} test_status;

const char *test_status_str[] = {
	"NOT RUN",
	"PASS",
	"FAIL"
};

#define	TEST_STATUS_STR(s)	(s < ARRAY_SIZE(test_status_str) ? \
				test_status_str[s] : "?")

struct bpf_helper_test {
	char *helper;
	char *test;
	char *description;
	char *cmd;
};

#define	DECLARE_BPF_HELPER_TEST(helper, test, description, cmd)		\
	{ #helper, #test, description, cmd }

#define	BPF_HELPER_TEST_NAME(helper, test, direction)			\
	#helper "_" #test "_" #direction

struct bpf_helper_test bpf_helper_tests[] = {
    DECLARE_BPF_HELPER_TEST(bpf_csum_diff, create,
			    "(from == 0, to > 0) create for IP",
			    "ping -q -c 1 10.1.1.200"),
    DECLARE_BPF_HELPER_TEST(bpf_csum_diff, add,
			    "(from > 0, to > 0) add data for IP",
			    "ping -q -c 1 10.1.1.200"),
    DECLARE_BPF_HELPER_TEST(bpf_csum_diff, remove,
			    "(from > 0, to == 0) remove data for ICMP",
			    "ping -q -c 1 10.1.1.200"),
    DECLARE_BPF_HELPER_TEST(bpf_l3_csum_replace, by_field,
			    "(from > 0, size > 0) replace for IP",
			    "ping -q -c 1 10.1.1.200"),
    DECLARE_BPF_HELPER_TEST(bpf_l3_csum_replace, by_sum,
			    "(from == 0, size == 0) replace for IP",
			    "ping -q -c 1 10.1.1.200"),
    DECLARE_BPF_HELPER_TEST(bpf_l4_csum_replace, by_field2,
			    "(flags == 2) replace for ICMP",
			    "ping -q -c 1 10.1.1.200"),
    DECLARE_BPF_HELPER_TEST(bpf_l4_csum_replace, by_field4,
			    "(flags == 4) replace for ICMP",
			    "ping -q -c 1 10.1.1.200"),
    DECLARE_BPF_HELPER_TEST(bpf_l4_csum_replace, by_diff,
			    "(flags == 0 ) replace for ICMP",
			    "ping -q -c 1 10.1.1.200"),
    DECLARE_BPF_HELPER_TEST(bpf_clone_redirect, in,
			    "redirect with BPF_F_INGRESS for ICMP",
			    "ping -q -c 1 10.1.1.200"),
    DECLARE_BPF_HELPER_TEST(bpf_clone_redirect, out, 
			    "redirect with BPF_F_EGRESS for ICMP",
			    "ping -q -c 1 10.1.1.200"),
    DECLARE_BPF_HELPER_TEST(bpf_redirect, in,
			    "redirect with BPF_F_INGRESS for ICMP",
			    "ping -q -c 1 10.1.1.200"),
    DECLARE_BPF_HELPER_TEST(bpf_redirect, out,
			    "redirect with BPF_F_EGRESS for ICMP",
			    "ping -q -c 1 10.1.1.200"),
    DECLARE_BPF_HELPER_TEST(bpf_skb_change_proto, ipv4toipv6,
			    "convert IPv4 -> IPv6 and back",
			    "ping -q -c 1 10.1.1.200"),

};

#define BPF_HELPER_TEST_MAP		"bpf_helper_test_map"

/* Local address 10.1.1.200, remote 10.1.1.100 */
#define	BPF_HELPER_IPV4_LOCAL		bpf_htonl(0xa0101c8)
#define	BPF_HELPER_IPV4_REMOTE		bpf_htonl(0xa010164)

/* Local addres fd01::22, remote fd01::11 */
#define BPF_HELPER_IPV6_PREFIX		bpf_htonl(0xfd010000)
#define	BPF_HELPER_IPV6_LOCAL_SUFFIX	bpf_htonl(0x22)
#define	BPF_HELPER_IPV6_REMOTE_SUFFIX	bpf_htonl(0x11)
