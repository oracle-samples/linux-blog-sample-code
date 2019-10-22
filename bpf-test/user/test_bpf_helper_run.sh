#!/bin/bash
#
# Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA

# BPF tc helper test suite setup/teardown
#   Here we setup and teardown configuration required to run BPF
#   tc helper tests.  The premise of the tests is simple;
#
#	- ping an IP address configured on top of a veth in the non-root
#	  namespace
#	- tc filters configured on that device will mangle the ICMP request
#	  on ingress, testing the relevant BPF helper function in the process.
#	  The intent however is to ensure it still gets passed up to the
#	  Linux networking stack as a valid packet.
#	- The ICMP reply is then mangled back to recover the original state.
#
#   Setup is similar to test_tunnel tests but without the tunnel.
#
# Topology:
# ---------
#     root namespace   |     tc_ns0 namespace
#                      |
#      ----------      |     ----------
#      |  veth1  | --------- |  veth0  |
#      ----------    peer    ----------
#
# Device Configuration
# --------------------
# Root namespace with BPF
# Device names and addresses:
#	veth1 IP: 10.1.1.200, 10.1.2.200, IPv6: fd01::22
#	BPF ingress/egress filters added to veth1.
#
# Namespace tc_ns0 with BP
# Device names and addresses:
#       veth0 IPv4: 10.1.1.100, 10.1.2.200 IPv6: fd01::11
#	Pings originate from here.
#
#
# End-to-end ping packet flow
# ---------------------------
# 1) BPF ingress/egress filters are configured for the test on veth1
#    in root namespace.
# 2) From the tc_ns0 namespace, ping IPv4/IPv6 address associated with
#    veth1 in the root namespace (e.g. 10.1.1.200)
# 2) veth1 ingress filter will run, mangle the packet and if all goes
#    well will mark the test as TEST_PASS in the test status BPF map.
# 3) Packet should be passed up to ICMP processing and (since it is
#    still destined for a valid address) a reply should be generated.
# 4) veth1 egress filter should mangle the reply such that it resembles
#    what the ICMP reply would have looked like had we not mangled it.
# 5) the ICMP reply should be recieved, and the test will pass if it is
#    and the ingress/egress filters did not set TEST_FAIL.

export TARGET_IPS="10.1.1.100/24 10.1.2.100/24 fd01::11/16"
export TARGET_NS="tc_ns0"

export LOCAL_IPS="10.1.1.200/24 10.1.2.200/24 fd01::22/16"

setup()
{
	ip netns add $TARGET_NS
	ip link add veth0 type veth peer name veth1
	ip link set veth0 netns $TARGET_NS
	for TARGET_IP in $TARGET_IPS ; do
		ip netns exec $TARGET_NS ip addr add $TARGET_IP dev veth0
	done
	tc qdisc add dev veth1 clsact
	# Initialize dummy filter "helper_test_init" so map is available.
	tc filter add dev veth1 ingress bpf da \
	    obj ../bpf/test_bpf_helper_init_kern.o \
	    sec helper_test_init
	for LOCAL_IP in $LOCAL_IPS; do
		ip addr add $LOCAL_IP dev veth1
	done
	ip netns exec $TARGET_NS ip link set veth0 up
	ip link set veth1 up
	sleep 5
}

cleanup()
{
	ip netns exec $TARGET_NS tc qdisc del dev veth0 clsact 2>/dev/null
	ip netns delete $TARGET_NS 2>/dev/null
	ip link del veth1 2>/dev/null
}

export ARGS="$@"

trap cleanup 0 2 3 6 9

setup
./test_bpf_helper $ARGS -d veth1 -n $TARGET_NS
exit $?
