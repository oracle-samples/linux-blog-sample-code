/*
 ** Copyright (c) 2022, Oracle and/or its affiliates.
 **
 ** The Universal Permissive License (UPL), Version 1.0
 **
 ** Subject to the condition set forth below, permission is hereby granted to any
 ** person obtaining a copy of this software, associated documentation and/or data
 ** (collectively the "Software"), free of charge and under any and all copyright
 ** rights in the Software, and any and all patent rights owned or freely
 ** licensable by each licensor hereunder covering either (i) the unmodified
 ** Software as contributed to or provided by such licensor, or (ii) the Larger
 ** Works (as defined below), to deal in both
 ** 
 ** (a) the Software, and
 ** (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
 ** one is included with the Software (each a "Larger Work" to which the Software
 ** is contributed by such licensors),
 ** 
 ** without restriction, including without limitation the rights to copy, create
 ** derivative works of, display, perform, and distribute the Software and make,
 ** use, sell, offer for sale, import, export, have made, and have sold the
 ** Software and the Larger Work(s), and to sublicense the foregoing rights on
 ** either these or other terms.
 ** 
 ** This license is subject to the following condition:
 ** The above copyright notice and either this complete permission notice or at
 ** a minimum a reference to the UPL must be included in all copies or
 ** substantial portions of the Software.
 ** 
 ** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 ** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 ** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 ** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 ** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 ** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 ** SOFTWARE.
 */
#include <getopt.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "do_sysinfo.skel.h"

struct do_sysinfo_bpf *skel;

void cleanup(int sig)
{
	do_sysinfo_bpf__destroy(skel);
	if (sig)
		exit(1);
}

int main(int argc, char *argv[])
{
	struct sysinfo info = {};
	int err;

	skel = do_sysinfo_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "skeleton failed\n");
		cleanup(1);
		return 1;
	}

	err = do_sysinfo_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "attach failed: %d\n", err);
		cleanup(0);
		return 1;
	}
	
	signal(SIGINT, cleanup);
        signal(SIGTERM, cleanup);

	sysinfo(&info);
	cleanup(0);

	return 0;
}
