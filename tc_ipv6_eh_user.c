#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <linux/ipv6.h>
#include <stddef.h>
#include <unistd.h>
#include "tc_ipv6_eh.h"

#define MAP_DIR		"/sys/fs/bpf/tc/globals/"

#define NEXTHDR_HOP	0

#define STR(x)		STR2(x)
#define STR2(x)		#x
#define MAP_NAME_STR	""STR(MAP_NAME)""
#define MAP_PATH	MAP_DIR MAP_NAME_STR

int main(int argc, char **argv)
{
	struct exthdr_t exthdr;
	int fd, ret, key = 0;

	/* Retrieve the array map */
	fd = bpf_obj_get(MAP_PATH);
	if (fd < 0) {
		fprintf(stderr, "Error opening map: %s\n", strerror(errno));
		return 1;
	}

	exthdr.type_first_eh = NEXTHDR_HOP;
	exthdr.off_last_nxthdr = offsetof(struct ipv6_opt_hdr, nexthdr);

	exthdr.bytes_len = 8;

	memset(exthdr.bytes, 0, MAX_BYTES);
	exthdr.bytes[2] = 0x01;
	exthdr.bytes[3] = 0x04;

	/* Apply changes with lock */
	ret = bpf_map_update_elem(fd, &key, &exthdr, BPF_EXIST|BPF_F_LOCK);
	if (ret) {
		fprintf(stderr, "Error updating map: %s\n", strerror(errno));
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}
