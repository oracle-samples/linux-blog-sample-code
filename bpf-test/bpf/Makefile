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

LLC ?= llc
CLANG ?= clang
INC_FLAGS = -nostdinc -isystem $(shell $(CLANG) -print-file-name=include)
EXTRA_CFLAGS ?= -O2 -g -Wall -emit-llvm

# In case up-to-date headers are not installed locally in /usr/include,
# use source build.

linuxhdrs ?= /usr/src/kernels/`uname -r`
LINUXINCLUDE =	-I$(linuxhdrs)/arch/x86/include/uapi \
		-I$(linuxhdrs)/arch/x86/include/generated/uapi \
		-I$(linuxhdrs)/arch/x86/include \
		-I$(linuxhdrs)/include/generated/uapi \
		-I$(linuxhdrs)/include/uapi \
		-I$(linuxhdrs)/include

KERNELOBJS =	test_bpf_helper_init_kern.o \
		test_bpf_helper_bpf_csum_diff_kern.o \
		test_bpf_helper_bpf_l3_csum_replace_kern.o \
		test_bpf_helper_bpf_l4_csum_replace_kern.o \
		test_bpf_helper_bpf_clone_redirect_kern.o \
		test_bpf_helper_bpf_redirect_kern.o \
		test_bpf_helper_bpf_skb_change_proto_kern.o

KERNELOBJDUMPS = $(KERNELOBJS:%.o=%.objdump)

prefix ?= /usr/local

INSTALLPATH = $(prefix)/lib/bpf

all: $(KERNELOBJS)

debug: DEBUG_FLAGS = -DBPFDEBUG
debug: all
	
.PHONY: clean

clean:
	rm -f $(KERNELOBJS) $(KERNELOBJDUMPS)

test:
	
LLC ?= llc
CLANG ?= clang
LLVM_OBJDUMP ?= llvm-objdump

install_PROGRAM = install
install_DIR = install -dv

$(KERNELOBJS):  %.o:%.c
	$(CLANG) $(INC_FLAGS) \
                -D__KERNEL__ -D__ASM_SYSREG_H \
		$(DEBUG_FLAGS) \
		-Wno-unused-value -Wno-pointer-sign \
                -Wno-compare-distinct-pointer-types \
                -Wno-gnu-variable-sized-type-not-at-end \
                -Wno-address-of-packed-member -Wno-tautological-compare \
                -Wno-unknown-warning-option \
		-I../include $(LINUXINCLUDE) \
		$(EXTRA_CFLAGS) -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@


$(KERNELOBJDUMPS): %.objdump:%.o
	$(LLVM_OBJDUMP) -S -no-show-raw-insn $< > $@

objdump: $(KERNELOBJDUMPS)
	
install: $(KERNELOBJS)
	$(install_DIR) -d $(INSTALLPATH) ; \
	$(install_PROGRAM) $^ -t $(INSTALLPATH)


uninstall: $(KERNELOBJS)
	rm -rf $(INSTALLPATH)
