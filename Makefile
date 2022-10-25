#
# Copyright (c) 2022, Oracle and/or its affiliates. All rights reserved.
#
#
# The Universal Permissive License (UPL), Version 1.0
#
# Subject to the condition set forth below, permission is hereby granted to any
# person obtaining a copy of this software, associated documentation and/or data
# (collectively the "Software"), free of charge and under any and all copyright
# rights in the Software, and any and all patent rights owned or freely
# licensable by each licensor hereunder covering either (i) the unmodified
# Software as contributed to or provided by such licensor, or (ii) the Larger
# Works (as defined below), to deal in both
#
# (a) the Software, and
# (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
# one is included with the Software (each a "Larger Work" to which the Software
# is contributed by such licensors),
#
# without restriction, including without limitation the rights to copy, create
# derivative works of, display, perform, and distribute the Software and make,
# use, sell, offer for sale, import, export, have made, and have sold the
# Software and the Larger Work(s), and to sublicense the foregoing rights on
# either these or other terms.
#
# This license is subject to the following condition:
# The above copyright notice and either this complete permission notice or at
# a minimum a reference to the UPL must be included in all copies or
# substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#
#
SRCARCH := $(shell uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/ \
                                  -e /arm64/!s/arm.*/arm/ -e s/sa110/arm/ \
                                  -e s/aarch64.*/arm64/ )
CLANG ?= clang
LLC ?= llc
# assumes libbpf/bpftool built and installed in /usr/local
BPFDIR := /usr/local
BPFTOOL ?= $(BPFDIR)/sbin/bpftool
BPF_INCLUDE := $(BPFDIR)/include
INCLUDES := -I$(BPF_INCLUDE)
LIBDIR := $(BPFDIR)/lib64

INSTALL ?= install

CFLAGS := -g -Wall

VMLINUX_BTF_PATH := /sys/kernel/btf/vmlinux

ifeq ($(V),1)
Q =
else
Q = @
MAKEFLAGS += --no-print-directory
submake_extras := feature_display=0
endif

.DELETE_ON_ERROR:

.PHONY: all clean $(PROG)

SRCS := do_sysinfo.c mallocation.c usdt_example.c

PROGS := $(SRCS:.c=)

OBJS := $(SRCS:.c=.o)

BPFOBJS := $(SRCS:.c=.bpf)

BPFSKELS := $(SRCS:.c=.skel.h)

all: $(PROGS)
	
clean:
	$(call QUIET_CLEAN, $(PROGS))
	$(Q)$(RM) *.o $(PROGS)
	$(Q)$(RM) *.skel.h vmlinux.h

install: $(PROGS)
	$(Q)$(INSTALL) -m 0755 -d $(DESTDIR)$(prefix)/sbin
	$(Q)$(INSTALL) $(PROGS) $(DESTDIR)$(prefix)/sbin

$(PROGS): $(OBJS)
	$(QUIET_LINK)$(CC) $(CFLAGS) $(@:%=%.o) -L$(LIBDIR) -lbpf -o $@

$(BPFSKELS): $(BPFOBJS)
	$(QUIET_GEN)$(BPFTOOL) gen skeleton $(@:%.skel.h=%.bpf.o) > $@

$(BPFOBJS): vmlinux.h
	$(QUIET_GEN)$(CLANG) -g -D__TARGET_ARCH_$(SRCARCH) -O2 -target bpf \
		-mcpu=probe -I$(INCLUDES) -c $@.c -o $@.o

$(OBJS): $(BPFSKELS)
	$(QUIET_CC)$(CC) $(CFLAGS) $(INCLUDES) -c $(@:%.o=%.c) -o $@

vmlinux.h:
	$(QUIET_GEN)$(BPFTOOL) btf dump file $(VMLINUX_BTF_PATH) format c > $@


