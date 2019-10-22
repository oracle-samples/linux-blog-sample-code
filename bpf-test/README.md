# BPF helper unit tests

The code here implements a set of BPF helper unit tests and also serves
as an example of how to set up an out-of-tree BPF build environment.

# How the tests work

They are all tc-based BPF programs which mangle ICMP ingress/egress packets
in order to test the various BPF helpers.  tc is a good choice because it
supports so many helper functions and loading BPF programs can be done
directly using tc.

# Building/running tests

1. Ensure libelf-devel/llvm/clang are installed.  For Oracle Linux systems,
to install libelf/clang/llvm on Oracle Linux 7, run:

```
$ yum install --enablerepo=ol7_optional_latest elfutils-libelf-devel elfutils-devel

$ yum install -y --enablerepo=ol7_developer rh-dotnet20-clang\* rh-dotnet20-llvm\* rh-dotnet20-cmake\*
```

2. Ensure recent kernel-uek-devel package or equivalent is present (e.g. 4.14),
and most recent iproute/iproute-tc packages.  The former is needed for
header files; the latter to allow us to load BPF programs directly via tc
(see tc-bpf(8) for more details):

```
# yum-config-manager --enable ol7_UEKR5
# yum install -y kernel-uek-devel iproute iproute-tc
```

3. Run "make test" to build/run tests

Befure running tests (if we use the SCL versions of clang/llvm) we need to
enable them the rh-dotnet20 sofware collection. Running the tests looks like
this:

```
# scl enable rh-dotnet20 bash
# make test
make  -C bpf test
make[1]: Entering directory `/home/almagui/src/upstream/bpf-test/bpf'
make[1]: `test' is up to date.
make[1]: Leaving directory `/home/almagui/src/upstream/bpf-test/bpf'
make  -C user test
make[1]: Entering directory `/home/almagui/src/upstream/bpf-test/user'
bash test_bpf_helper_run.sh
Note: 8 bytes struct bpf_elf_map fixup performed due to size mismatch!
Test case: bpf_csum_diff/create (from == 0, to > 0) create for IP PASS
Test case: bpf_csum_diff/add (from > 0, to > 0) add data for IP PASS
Test case: bpf_csum_diff/remove (from > 0, to == 0) remove data for ICMP PASS
Test case: bpf_l3_csum_replace/by_field (from > 0, size > 0) replace for IP PASS
Test case: bpf_l3_csum_replace/by_sum (from == 0, size == 0) replace for IP PASS
Test case: bpf_l4_csum_replace/by_field2 (flags == 2) replace for ICMP PASS
Test case: bpf_l4_csum_replace/by_field4 (flags == 4) replace for ICMP PASS
Test case: bpf_l4_csum_replace/by_diff (flags == 0 ) replace for ICMP PASS
Test case: bpf_clone_redirect/in redirect with BPF_F_INGRESS for ICMP PASS
Test case: bpf_clone_redirect/out redirect with BPF_F_EGRESS for ICMP PASS
Test case: bpf_redirect/in redirect with BPF_F_INGRESS for ICMP PASS
Test case: bpf_redirect/out redirect with BPF_F_EGRESS for ICMP PASS
Test case: bpf_skb_change_proto/ipv4toipv6 convert IPv4 -> IPv6 and back PASS

Summary: 13 PASSED, 0 FAILED
```

Individual tests can be run via the test_bpf_helper_run.sh script, e.g.
to run the bpf_skb_change_proto helper test "ipv4toipv6":

```
# bash test_bpf_helper_run.sh -h bpf_skb_change_proto -t ipv4toipv6
```

# Layout

BPF components of tests are under bpf/ , userland side under usr/ .
A few bits and pieces from kernel tree are present too to simplify the build
environment and avoid having to have a full set of kernel headers present.

# Internals

Tests maintain a BPF map of test status with one entry per test. Tests
can mark cases explicitly as failed/passed in BPF context, and both the
command (usually a ping) and the test status have to show success for a
test to succeed.

To add a new test for a helper

1. create a test_bpf_helper_<helper_name>.c file

2. add macros for ingress/egress actions, e.g. for the "in" test for
bpf_clone_redirect() add a file called test_bpf_helper_bpf_clone_redirect.c
containing:

```

#include "test_bpf_helper_kern.h"

BPF_HELPER_TEST_FUNC(bpf_clone_redirect, in, ingress)
{
	...
}


BPF_HELPER_TEST_FUNC(bpf_clone_redirect, in, egress)
{
	...
}
```

The file should be added under bpf/ and should #include "test_bpf_helper_kern.h"

3. add a test entry to include/test_bpf_helper.h's bpf_helper_tests[]
array, specifying
	- helper name
	- test name
	- test description
	- associated command to run when executing test (usually a ping)

