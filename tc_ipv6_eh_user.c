#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/rpl.h>
#include <linux/seg6.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tc_ipv6_eh.h"

#define MAP_DIR			"/sys/fs/bpf/tc/globals/"

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
#define MAX_BYTES_AH		((255 + 2) << 2)
#define MAX_BYTES_ESP		((MAX_BYTES) & (-8))

#define FLAGS_HBH		(1 << 0)
#define FLAGS_DEST1		(1 << 1)
#define FLAGS_RH		(1 << 2)
#define FLAGS_FRAG		(1 << 3)
#define FLAGS_AH		(1 << 4)
#define FLAGS_ESP		(1 << 5)
#define FLAGS_DEST2		(1 << 6)

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
	printf(" | %s %ld..%d", ARG_AH, MIN_BYTES_AH, MAX_BYTES_AH);
	printf(" | %s %ld..%d", ARG_ESP, MIN_BYTES_ESP, MAX_BYTES_ESP);
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

void print_missing_size(char *arg)
{
	printf("\nMissing size for \"%s\"\n", arg);
}

void print_invalid_size(char *arg)
{
	printf("\nInvalid size for \"%s\"\n", arg);
}

void print_not_rfc8200_compliant()
{
	printf("\nNot RFC8200 compliant, use \"--force\" to override\n");
}

void print_size_overflow(unsigned int max)
{
	printf("\nCannot exceed the total maximum size of %u bytes\n", max);
}

unsigned char valid_size(char *s, unsigned int min, unsigned int max, long *val)
{
	char *p;

	*val = strtol(s, &p, 10);
	if (!*val || strlen(p) > 0 || *val < min || *val > max || *val%8 != 0)
		return 0;

	return 1;
}

int main(int argc, char **argv)
{
	unsigned char flags = 0, force = 0;
	struct exthdr_t exthdr = {};
	unsigned int i, key = 0;
	int fd, ret;
	long n;

	if (argc < 2 || (argc == 2 && strcmp(argv[1], ARG_DISABLE)) ||
	    (argc > 2 && strcmp(argv[1], ARG_ENABLE)) ||
	    (argc == 3 && !strcmp(argv[2], ARG_FORCE)))
		goto error_out;

	if (!strcmp(argv[1], ARG_DISABLE))
		goto update_map;

	i = 2;
	if (!strcmp(argv[2], ARG_FORCE)) {
		i += 1;
		force = 1;
	}

	exthdr.off_last_nxthdr = MAX_BYTES;//TODO

	for(i; i < argc; i++) {
		if (!strcmp(argv[i], ARG_HBH)) {
			if (i+1 == argc) {
				print_missing_size(ARG_HBH);
				goto error_out;
			}

			i += 1;
			if (!valid_size(argv[i], MIN_BYTES, EH_MAX_BYTES, &n)) {
				print_invalid_size(ARG_HBH);
				goto error_out;
			}

			if (!force && flags) {
				print_not_rfc8200_compliant();
				goto error_out;
			}

			if (exthdr.bytes_len + n > MAX_BYTES) {
				print_size_overflow(MAX_BYTES);
				goto error_out;
			}

			struct ipv6_opt_hdr *opt = (void *)&exthdr.bytes[exthdr.bytes_len];
			opt->hdrlen = (n >> 3) - 1;
			//TODO insert in exthdr.bytes
			/*
			for(__u16 i = 2; i + 1 < *len; i += 257)
			{
				exthdr->bytes[i] = 0x1e;
				exthdr->bytes[i + 1] = MIN(*len - i - 2, 255);
			}
			*/

			//TODO if there is a previous EH with a next hdr field, set it to IPPROTO_HOPOPTS, else set exthdr.type_first_eh to IPPROTO_HOPOPTS
			//TODO set exthdr.off_last_nxthdr to the hbh nexthdr field offset
			/*
			exthdr.type_first_eh = NEXTHDR_HOP;
			exthdr.off_last_nxthdr = 0; //offsetof(struct ipv6_opt_hdr, nexthdr);
			*/

			exthdr.bytes_len += n;
			flags |= FLAGS_HBH;
		} else if (!strcmp(argv[i], ARG_DEST)) {
			//IPPROTO_DSTOPTS
		} else if (!strcmp(argv[i], ARG_RH0)) {
			//IPPROTO_ROUTING
		} else if (!strcmp(argv[i], ARG_RH2)) {
			//IPPROTO_ROUTING
		} else if (!strcmp(argv[i], ARG_RH3)) {
			//IPPROTO_ROUTING
		} else if (!strcmp(argv[i], ARG_RH4)) {
			//IPPROTO_ROUTING
		} else if (!strcmp(argv[i], ARG_FRAG_A)) {
			//IPPROTO_FRAGMENT
		} else if (!strcmp(argv[i], ARG_FRAG_NA)) {
			//IPPROTO_FRAGMENT
		} else if (!strcmp(argv[i], ARG_AH)) {
			//IPPROTO_AH
			//ah size = (total bytes / 4) - 2
		} else if (!strcmp(argv[i], ARG_ESP)) {
			//IPPROTO_ESP
		} else {
			printf("\nUnexpected argument \"%s\"\n", argv[i]);
			goto error_out;
		}
	}

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

error_out:
	print_help(argv[0]);
	return 1;
}
