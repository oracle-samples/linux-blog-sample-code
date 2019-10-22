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
#
# Build/run bpf helper tests.

SUBDIRS = bpf user
SUBDIRS_ALL = $(SUBDIRS:%=all-%)
SUBDIRS_DEBUG = $(SUBDIRS:%=debug-%)
SUBDIRS_INSTALL = $(SUBDIRS:%=install-%)
SUBDIRS_UNINSTALL = $(SUBDIRS:%=uninstall-%)
SUBDIRS_TEST = $(SUBDIRS:%=test-%)
SUBDIRS_CLEAN = $(SUBDIRS:%=clean-%)

PKG_DIR =  ~/rpmbuild/BUILDROOT/bpf-helper-test-1.1-1.`uname -p`
SOURCE_DIR = $(PKG_DIR)/SOURCES
BUILD_DIR = $(PKG_DIR)/BUILD
RPM_DIR = /var/tmp/bpf-helper-test/RPMS/`uname -p`

prefix ?= /usr/local

all: $(SUBDIRS_ALL)
	
debug: $(SUBDIRS_DEBUG)
	
install: $(SUBDIRS_INSTALL)
	

uninstall: $(SUBDIRS_UNINSTALL)
	
clean: $(SUBDIRS_CLEAN)
	
test: $(SUBDIRS_TEST)
	
	
pkg:
	mkdir -p $(SOURCE_DIR) $(BUILD_DIR) $(BUILD_DIR)/$(prefix) $(RPM_DIR) ;\
	prefix=$(PKG_DIR)/$(prefix) rpmbuild -bb --noclean bpf-helper-test.spec;\

$(SUBDIRS_ALL): FRC
	$(MAKE) $(MAKE_FLAGS) -C $(@:all-%=%) all

$(SUBDIRS_DEBUG): FRC
	$(MAKE) $(MAKE_FLAGS) -C $(@:debug-%=%) debug
$(SUBDIRS_INSTALL): FRC
	$(MAKE) $(MAKE_FLAGS) -C $(@:install-%=%) install

$(SUBDIRS_UNINSTALL): FRC
	$(MAKE) $(MAKE_FLAGS) -C $(@:uninstall-%=%) uninstall

$(SUBDIRS_CLEAN): FRC
	$(MAKE) $(MAKE_FLAGS) -C $(@:clean-%=%) clean

$(SUBDIRS_TEST): FRC
	$(MAKE) $(MAKE_FLAGS) -C $(@:test-%=%) test

.PHONY: clean

FRC:
	
