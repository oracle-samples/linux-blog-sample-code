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

/* Tool to run BPF helper tests. */

#include <uapi/linux/if_ether.h>
#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <netdb.h>
#include <uapi/linux/bpf.h>

#include "bpf_util.h"
#include "test_bpf_helper.h"

#define	MAP_PREFIX	"/sys/fs/bpf/tc/globals"

#define	REDIRECT_QUIET	">/dev/null 2>&1"

int map_fd = -1;

int verbose = 0;

char *filterpath = "../bpf/";
char *netns = "tc_ns0";
char *dev = NULL;
char *prog;

#define	LOG_ERR(i, fmt, ...)					\
	do {							\
		fprintf(stderr, "\n%s/%s : ",			\
		        bpf_helper_tests[i].helper,		\
		        bpf_helper_tests[i].test);		\
		fprintf(stderr, fmt, ##__VA_ARGS__);		\
		fprintf(stderr, "\n");				\
	} while (0)

#define	DO_SYSTEM(ret, fmt, ...)				\
	do {							\
		char cmd[256];					\
								\
		snprintf(cmd, sizeof(cmd), fmt, ##__VA_ARGS__); \
		if (!verbose)					\
			strncat(cmd, REDIRECT_QUIET,		\
				sizeof(cmd));			\
		ret = system(cmd);				\
	} while (0)

static void int_exit(int sig)
{
	close(map_fd);
	exit(1);
}

static void usage_exit(int err)
{
	fprintf(stderr,
		"usage: %s [OPTS] \n\n"
		"Run test(s):\n\n"
		"\t%s -n netns -d device [-v] [-h helper -t test] [-f path]\n"
		"\n\tSpecify device to add filters to via '-d device'."
		"\n\tSpecify verbose mode via '-v/V'."
		"\n\tSpecify test to run via '-h helper -t test'."
		"\n\tSpecify path to filter objects containing tests via "
		"'-f path'.\n"
		"\nList test(s) results from last run:\n\n"
		"\t%s -l [-h helper_name -t test]\n"
		"\n\tSpecify results to show via '-h helper -t test'.\n"
		"\nRemove test(s):\n\n"
		"\t%s -r\n\n",
		prog, prog, prog, prog);
	exit(err);
}

static int map_get(char *map_name)
{
	char pinned_file[256];

	snprintf(pinned_file, sizeof(pinned_file), "%s/%s",
		 MAP_PREFIX, map_name);

	return bpf_obj_get(pinned_file);
}

/* Either helper/test must match current test index, or if they are not
 * specified, we match (since this specifies "match all tests".
 */
static int match_test(const char *helper, const char *test, int i)
{
	return (helper == NULL && test == NULL) ||
	       (strcmp(helper, bpf_helper_tests[i].helper) == 0 &&
		strcmp(test, bpf_helper_tests[i].test) == 0);
}

static int list_tests(const char *helper, const char *test)
{
	long i = 0, status;
	int j;

	printf("%20s %20s %-6s %-30s\n",
	       "HELPER", "TEST", "STATUS", "DESCRIPTION");

	for (i = 0; i < ARRAY_SIZE(bpf_helper_tests); i++) {
		if (bpf_map_lookup_elem(map_fd, &i, &status) != 0)
			continue;
		if (!match_test(helper, test, i))
			continue;
		printf("%20s %20s %6s %.30s\n",
		       bpf_helper_tests[i].helper,
		       bpf_helper_tests[i].test,
		       TEST_STATUS_STR(status),
		       bpf_helper_tests[i].description);
		/* Support multiline descriptions. */
		for (j = 30; j < strlen(bpf_helper_tests[i].description); j+=30)
			printf("%40s %6s %.30s\n", "", "",
			       &bpf_helper_tests[i].description[j]);
				
	}
	return 0;
}

/* Add either
 *
 * - specific helper/test to test status map; or
 * - all tests to test status map
 *
 * Adding a test to the status map signals it is to be run; tests start in
 * the TEST_NOT_RUN state.
 */
static int add_tests(const char *helper, const char *test)
{
	long i, status = TEST_NOT_RUN;
	int added = 0;
	int ret = -1;

	for (i = 0; i < ARRAY_SIZE(bpf_helper_tests); i++) {
		if (!match_test(helper, test, i))
			continue;
		ret = bpf_map_update_elem(map_fd, &i, &status, BPF_ANY);
		if (ret)
			perror("error adding test\n");
		added++;
	}
	if (ret)
		fprintf(stderr, "could not add test(s)\n");

	return added;
}

/* Clear out test status map. */
static int remove_tests(void)
{
	long test = 0;

	for (test = 0; test < ARRAY_SIZE(bpf_helper_tests); test++)
		(void) bpf_map_delete_elem(map_fd, &test);

	return 0;
}

static int run_tests(const char *helper, const char *test)
{
	char *currhelper, *currtest, *currdesc, *currcmd;
	char *dir[] = { "ingress", "egress" };
	int j, failures = 0, ret;
	char *lasthelper = NULL;
	long i, status;

	for (i = 0; i < ARRAY_SIZE(bpf_helper_tests); i++) {

		currhelper = bpf_helper_tests[i].helper;
		currtest = bpf_helper_tests[i].test;
		currdesc = bpf_helper_tests[i].description;
		currcmd = bpf_helper_tests[i].cmd;

		if (!match_test(helper, test, i))
			continue;

		printf("Test case: %s/%s %s ", currhelper, currtest, currdesc);

		/* No need to reload filter if same helper... */
		if (!lasthelper || strcmp(lasthelper, currhelper) != 0) {
			for (j = 0; j < ARRAY_SIZE(dir); j++) {
				DO_SYSTEM(ret,
					  "tc filter add dev %s %s bpf da obj "
					  "%stest_bpf_helper_%s_kern.o "
					  "sec %s_%s_%s %s",
					  dev, dir[j], filterpath, currhelper,
					  currhelper, currtest, dir[j],
					  verbose > 1 ? "verbose" : "");
				if (ret) {
					LOG_ERR(i,
						"error adding %s filter (%d)",
						dir[j], ret);
					failures++;
					break;
				}
			}
			if (ret)
				continue;
		}
		lasthelper = currhelper;

		if (ret)
			continue;

		/* For a test to succeed, the associated command needs to
		 * succeed _and_ the BPF map entry needs to be marked as
		 * TEST_PASS.
		 */
		DO_SYSTEM(ret, "ip netns exec %s %s", netns, currcmd);
		if (ret) {
			LOG_ERR(i, "command (%s) returned error (%d)",
				currcmd, ret);
			status = TEST_FAIL;
		} else {
			ret = bpf_map_lookup_elem(map_fd, &i, &status);
			if (ret) {
				LOG_ERR(i, "error looking up test status (%d)",
					strerror(errno));
				status = TEST_FAIL;
			}
		}
		if (status != TEST_PASS) {
			status = TEST_FAIL;
			(void) bpf_map_update_elem(map_fd, &i, &status,
						   BPF_ANY);
			failures++;
		}
		printf("%s\n", TEST_STATUS_STR(status));
	}
        return failures;
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	char *map_name = BPF_HELPER_TEST_MAP;
	const char *optstr = "d:f:h:n:t:lrvV";
	int list = 0, remove = 0;
	char pinned_file[256];
	char *helper = NULL;
	int added, failures;
	char *test = NULL;
	int opt, ret = -1;

	prog = argv[0];

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		case 'd':
			dev = optarg;
			break;
		case 'f':
			filterpath = optarg;
			break;
		case 'h':
			helper = optarg;
			break;
		case 'l':
			list = 1;
			break;
		case 'n':
			netns = optarg;
			break;
		case 't':
			test = optarg;
			break;
		case 'r':
			remove = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'V':
			verbose = 2;
			break;
		default:
			fprintf(stderr, "Unknown option '%c'.\n", optopt);
			usage_exit(1);
		}
	}

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	map_fd = map_get(map_name);
	if (map_fd < 0) {
		fprintf(stderr, "could not find map %s: %s\n",
			map_name, strerror(errno));
		return 1;
	}

	if (list)
		ret = list_tests(helper, test);
	else if (remove)
		ret = remove_tests();
	else {
		if (dev == NULL || netns == NULL) {
			fprintf(stderr,
				"'-d device -n netns' must be specified\n");
			usage_exit(1);
		}
		ret = remove_tests();
		if (ret)
			fprintf(stderr, "Could not remove tests.\n");
		else {
			added = add_tests(helper, test);
			if (added)
				failures = run_tests(helper, test);
			else
				fprintf(stderr, "No tests added.");
		}
		printf("\nSummary: %d PASSED, %d FAILED\n", added - failures,
		       failures);

		if (failures == 0 && added > 0)
			ret = 0;
	}
	close(map_fd);

	return ret;
}
