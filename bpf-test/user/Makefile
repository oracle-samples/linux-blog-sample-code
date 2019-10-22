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
#
# Build bpf code (kernel and userspace) out-of-tree by referencing
# local copies of bpf .c and .h files along with bcc headers.
#
# Assumptions:
# - kernel headers for approximately the same build as is running are in place
# - LLVM/clang/bcc are available

COMMONOBJS = bpf.o

TESTPROG= test_bpf_helper
TESTOBJS = $(TESTPROG).o

PROGS= $(TESTPROG)

OBJS= $(COMMONOBJS) $(TESTOBJS)

SCRIPTS= test_bpf_helper_run.sh

linuxhdrs ?= /usr/src/kernels/`uname -r`

LINUXINCLUDE =  -I$(linuxhdrs)/arch/x86/include/uapi \
                -I$(linuxhdrs)/arch/x86/include/generated/uapi \
                -I$(linuxhdrs)/include/generated/uapi \
                -I$(linuxhdrs)/include/uapi \
                -I$(linuxhdrs)/include

prefix ?= /usr/local

INSTALLPATH = $(prefix)/bin

install_PROGRAM = install
install_DIR = install -d

LDLIBS = -lelf

all: $(TESTPROG)
	
debug: all
	
.PHONY: clean

clean:
	rm -f $(OBJS) $(PROGS)

test:
	bash test_bpf_helper_run.sh

%.o: %.c
	$(CC) $(DEBUG_FLAGS) -g -Wno-unused-variable -I../include $(LINUXINCLUDE) -c -o $@ $< $(CFLAGS)

$(PROGS): $(OBJS)
	$(CC) -g -o $@ $(@).o $(COMMONOBJS) $(CFLAGS) $(LDLIBS)

$(SCRIPTS):
	

install: $(PROGS) $(SCRIPTS)
	$(install_DIR) -d $(INSTALLPATH) ; \
	$(install_PROGRAM) $^ -t $(INSTALLPATH)

uninstall: $(PROGS) $(SCRIPTS)
	cd $(INSTALLPATH); rm -f $^
