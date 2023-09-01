#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/rpl.h>
#include <linux/seg6.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "tc_ipv6_eh.h"

#define MAP_DIR			"/sys/fs/bpf/tc/globals/"

#define NEXTHDR_HOP		0	/* Hop-by-hop options header */
#define NEXTHDR_ROUTING		43	/* Routing header */
#define NEXTHDR_FRAGMENT	44	/* Fragmentation header */
#define NEXTHDR_ESP		50	/* Encapsulating security payload */
#define NEXTHDR_AUTH		51	/* Authentication header */
#define NEXTHDR_DEST		60	/* Destination options header */

#define ARG_ENABLE		"--enable"
#define ARG_DISABLE		"--disable"
#define ARG_FORCE		"--force"
#define ARG_HBH			"--hbh"
#define ARG_DEST		"--dest"
#define ARG_RH0			"--rh0"
#define ARG_RH2			"--rh2"
#define ARG_RH3			"--rh3"
#define ARG_RH4			"--rh4"
#define ARG_FRAG_A		"--fragA"
#define ARG_FRAG_NA		"--fragNA"
#define ARG_AH			"--ah"
#define ARG_ESP			"--esp"

#define MIN_BYTES_RH0		(sizeof(struct rt0_hdr) + sizeof(struct in6_addr))
#define MIN_BYTES_RH3		(sizeof(struct ipv6_rpl_sr_hdr) + sizeof(struct in6_addr))
#define MIN_BYTES_RH4		(sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr))
#define MIN_BYTES_AH		(sizeof(struct ip_auth_hdr) + 4)
#define MIN_BYTES_ESP		(sizeof(struct ip_esp_hdr) + 8)

#define STR(x)			STR2(x)
#define STR2(x)			#x
#define MAP_NAME_STR		""STR(MAP_NAME)""
#define MAP_PATH		MAP_DIR MAP_NAME_STR

void print_help(char *prog_name)
{
	printf("\nUsage: %s { --disable", prog_name);
	printf(" | --enable [ --force ] EXTHDR [ EXTHDR ] }\n\n");
	printf("EXTHDR := {");
	printf(" %s %d..%d", ARG_HBH, MIN_BYTES, EH_MAX_BYTES);
	printf(" | %s %d..%d", ARG_DEST, MIN_BYTES, EH_MAX_BYTES);
	printf(" | %s %ld..%d", ARG_RH0, MIN_BYTES_RH0, EH_MAX_BYTES);
	printf(" | %s", ARG_RH2);
	printf(" | %s %ld..%d", ARG_RH3, MIN_BYTES_RH3, EH_MAX_BYTES);
	printf(" | %s %ld..%d", ARG_RH4, MIN_BYTES_RH4, EH_MAX_BYTES);
	printf(" | %s | %s", ARG_FRAG_A, ARG_FRAG_NA);
	printf(" | %s %ld..%d", ARG_AH, MIN_BYTES_AH, 123/*TODO*/);
	printf(" | %s %ld..%d", ARG_ESP, MIN_BYTES_ESP, MAX_BYTES);
	printf(" }\n\n");
	printf("If a size is required, it MUST be an 8-octet multiple.\n\n");
	printf("Accepted chaining order, as per RFC8200 sec4.1:\n");
	printf(" - Hop-by-Hop Options header\n");
	printf(" - Destination Options header\n");
	printf(" - Routing header\n");
	printf(" - Fragment header\n");
	printf(" - Authentication header\n");
	printf(" - Encapsulating Security Payload header\n");
	printf(" - Destination Options header\n");
}

int main(int argc, char **argv)
{
	unsigned char rfc_order = 1, flags = 0, forced = 0;
	unsigned int i, len = 0, key = 0;
	struct exthdr_t exthdr = {};
	int fd, ret;

	if (argc < 2 || (argc == 2 && strcmp(argv[1], ARG_DISABLE)) ||
	    (argc > 2 && strcmp(argv[1], ARG_ENABLE)) ||
	    (argc == 3 && !strcmp(argv[2], ARG_FORCE))) {
		print_help(argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], ARG_DISABLE))
		goto update_map;

	i = 2;
	if (!strcmp(argv[2], ARG_FORCE)) {
		i++;
		forced = 1;
	}

	for(i; i < argc; i++) {
		printf("argv[%d] = %s\n", i, argv[i]);

		if (!strcmp(argv[i], ARG_HBH)) {
			/*if (flags)
				rfc_order = 0;*/
		} else if (!strcmp(argv[i], ARG_DEST)) {
		} else if (!strcmp(argv[i], ARG_RH0)) {
		} else if (!strcmp(argv[i], ARG_RH2)) {
		} else if (!strcmp(argv[i], ARG_RH3)) {
		} else if (!strcmp(argv[i], ARG_RH4)) {
		} else if (!strcmp(argv[i], ARG_FRAG_A)) {
		} else if (!strcmp(argv[i], ARG_FRAG_NA)) {
		} else if (!strcmp(argv[i], ARG_AH)) {
		} else if (!strcmp(argv[i], ARG_ESP)) {
		} else {
			printf("Unexpected argument \"%s\"\n", argv[i]);
			print_help(argv[0]);
			return 1;
		}
	}
	/*
	exthdr.type_first_eh = NEXTHDR_HOP;
	exthdr.off_last_nxthdr = 0; //offsetof(struct ipv6_opt_hdr, nexthdr);
	exthdr.bytes_len = 8;
	exthdr.bytes[2] = 0x01;
	exthdr.bytes[3] = 0x04;
	*/

update_map:
	/* Retrieve the array map */
	fd = bpf_obj_get(MAP_PATH);
	if (fd < 0) {
		fprintf(stderr, "Error opening map: %s\n", strerror(errno));
		return 1;
	}

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
