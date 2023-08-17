#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "tc_ipv6_eh.h"

#define MAP_DIR		"/sys/fs/bpf/tc/globals/"

#define STR(x)		STR2(x)
#define STR2(x)		#x
#define MAP_NAME_STR	""STR(MAP_NAME)""

#define MAP_PATH	MAP_DIR MAP_NAME_STR

int main(int argc, char **argv)
{
	struct exthdr_t value;
	int fd, ret, key = 0;

	/* Retrieve the array map */
	fd = bpf_obj_get(MAP_PATH);
	if (fd < 0) {
		fprintf(stderr, "Error opening map: %s\n", strerror(errno));
		return 1;
	}

	value.enabled = 77;
	memset(value.bytes, 0, EH_MAX_BYTES);

	/* Apply changes with lock */
	ret = bpf_map_update_elem(fd, &key, &value, BPF_EXIST|BPF_F_LOCK);
	if (ret) {
		fprintf(stderr, "Error updating map: %s\n", strerror(errno));
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}
