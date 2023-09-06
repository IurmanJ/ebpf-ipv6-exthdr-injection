#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/rpl.h>
#include <linux/seg6.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

#define MIN_BYTES_HBH		8
#define MIN_BYTES_DEST		MIN_BYTES_HBH
#define MIN_BYTES_RH0		(sizeof(struct rt0_hdr) + sizeof(struct in6_addr))
#define MIN_BYTES_RH3		(sizeof(struct ipv6_rpl_sr_hdr) + sizeof(struct in6_addr))
#define MIN_BYTES_RH4		(sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr))
#define MIN_BYTES_AH		(sizeof(struct ip_auth_hdr) + 4)
#define MIN_BYTES_ESP		(sizeof(struct ip_esp_hdr) + 8)

#define MAX_BYTES_HBH		((255 + 1) << 3)
#define MAX_BYTES_DEST		MAX_BYTES_HBH
#define MAX_BYTES_RH0		(255 << 3)
#define MAX_BYTES_RH3		MAX_BYTES_RH0
#define MAX_BYTES_RH4		MAX_BYTES_RH0
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

#define MIN(a,b)		((a)<(b) ? (a):(b))

struct frag_hdr {
	__u8	nexthdr;
	__u8	reserved;
	__be16	frag_off;
	__be32	identification;
};

void print_help(const char *prog_name) {
	printf("\nUsage: %s { --disable", prog_name);
	printf(" | --enable [ --force ] EXTHDR [ EXTHDR ] }\n\n");
	printf("EXTHDR := {");
	printf(" %s %d..%d", ARG_HBH, MIN_BYTES_HBH, MAX_BYTES_HBH);
	printf(" | %s %d..%d", ARG_DEST, MIN_BYTES_DEST, MAX_BYTES_DEST);
	printf(" | %s %ld..%d", ARG_RH0, MIN_BYTES_RH0, MAX_BYTES_RH0);
	printf(" | %s", ARG_RH2);
	printf(" | %s %ld..%d", ARG_RH3, MIN_BYTES_RH3, MAX_BYTES_RH3);
	printf(" | %s %ld..%d", ARG_RH4, MIN_BYTES_RH4, MAX_BYTES_RH4);
	printf(" | %s | %s", ARG_FRAG_A, ARG_FRAG_NA);
	printf(" | %s %ld..%d", ARG_AH, MIN_BYTES_AH, MAX_BYTES_AH);
	printf(" | %s %ld..%d", ARG_ESP, MIN_BYTES_ESP, MAX_BYTES_ESP);
	printf(" }\n\n");
	printf("If a size is required, it MUST be an 8-octet multiple.\n");
	printf("Routing Header sizes minus 8 MUST be 16-octet multiples.\n\n");
	printf("Accepted chaining order, as per RFC8200 sec4.1:\n");
	printf(" - Hop-by-Hop Options header\n");
	printf(" - Destination Options header\n");
	printf(" - Routing header\n");
	printf(" - Fragment header\n");
	printf(" - Authentication header\n");
	printf(" - Encapsulating Security Payload header\n");
	printf(" - Destination Options header\n");
}

void print_missing_size(const char *arg) {
	printf("\nMissing size for \"%s\"\n", arg);
}

void print_invalid_size(const char *arg) {
	printf("\nInvalid size for \"%s\"\n", arg);
}

void print_not_rfc8200_compliant() {
	printf("\nNot RFC8200 compliant, use \"--force\" to override\n");
}

void print_size_overflow(__u32 max) {
	printf("\nCannot exceed the total maximum size of %u bytes\n", max);
}

__u8 valid_size(const char *str, __u32 min, __u32 max, long *val) {
	char *p;

	*val = strtol(str, &p, 10);
	if (!*val || strlen(p) > 0 || *val < min || *val > max || *val%8 != 0)
		return 0;

	return 1;
}

void random_ip6addr(struct in6_addr *addr) {
	/* Used range: 2a00:0000::/12 (RIPE NCC) */
	addr->s6_addr[0] = 0x2a;
	addr->s6_addr[1] = 0x00;

	for(unsigned int i = 2; i < sizeof(*addr); i++)
		addr->s6_addr[i] = rand();
}

int main(int argc, char **argv) {
	struct exthdr_t exthdr = {};
	unsigned int i, j, key = 0;
	__u8 flags = 0, force = 0;
	int fd, ret;
	long n;

	if (argc < 2 || (argc == 2 && strcmp(argv[1], ARG_DISABLE)) ||
	    (argc > 2 && strcmp(argv[1], ARG_ENABLE)) ||
	    (argc == 3 && !strcmp(argv[2], ARG_FORCE))) {
		goto error_out;
	}

	if (!strcmp(argv[1], ARG_DISABLE))
		goto update_map;

	i = 2;
	if (!strcmp(argv[2], ARG_FORCE)) {
		i += 1;
		force = 1;
	}

	srand(time(NULL));
	for(i; i < argc; i++) {
		if (!strcmp(argv[i], ARG_HBH)) {
			if (i+1 == argc) {
				print_missing_size(ARG_HBH);
				goto error_out;
			}

			i += 1;
			if (!valid_size(argv[i], MIN_BYTES_HBH, MAX_BYTES_HBH, &n)) {
				print_invalid_size(ARG_HBH);
				goto error_out;
			}

			if (!force && (flags & (FLAGS_HBH | FLAGS_DEST1 |
						FLAGS_RH | FLAGS_FRAG |
						FLAGS_AH | FLAGS_ESP |
						FLAGS_DEST2))) {
				print_not_rfc8200_compliant();
				goto error_out;
			}
			flags |= FLAGS_HBH;

			if (exthdr.bytes_len + n > MAX_BYTES) {
				print_size_overflow(MAX_BYTES);
				goto error_out;
			}

			struct ipv6_opt_hdr *opt = (void *)&exthdr.bytes[exthdr.bytes_len];
			opt->hdrlen = (n >> 3) - 1;

			//TODO randomize bytes for options
			for(j = sizeof(*opt); j+1 < n; j += 257) {
				exthdr.bytes[exthdr.bytes_len+j] = 0x1e;
				exthdr.bytes[exthdr.bytes_len+j+1] = MIN(n-j-sizeof(*opt), 255);
			}

			if (exthdr.bytes_len == 0) {
				exthdr.ip6nexthdr = IPPROTO_HOPOPTS;
			} else if (exthdr.off_last_nexthdr != MAX_BYTES) {
				exthdr.bytes[exthdr.off_last_nexthdr] = IPPROTO_HOPOPTS;
			}

			exthdr.off_last_nexthdr = exthdr.bytes_len
				+ offsetof(struct ipv6_opt_hdr, nexthdr);
			exthdr.bytes_len += n;
		} else if (!strcmp(argv[i], ARG_DEST)) {
			if (i+1 == argc) {
				print_missing_size(ARG_DEST);
				goto error_out;
			}

			i += 1;
			if (!valid_size(argv[i], MIN_BYTES_DEST, MAX_BYTES_DEST, &n)) {
				print_invalid_size(ARG_DEST);
				goto error_out;
			}

			if (!force && (flags & FLAGS_DEST2)) {
				print_not_rfc8200_compliant();
				goto error_out;
			}
			if (!(flags & (FLAGS_DEST1 | FLAGS_RH | FLAGS_FRAG |
					FLAGS_AH | FLAGS_ESP)))
				flags |= FLAGS_DEST1;
			else
				flags |= FLAGS_DEST2;

			if (exthdr.bytes_len + n > MAX_BYTES) {
				print_size_overflow(MAX_BYTES);
				goto error_out;
			}

			struct ipv6_opt_hdr *opt = (void *)&exthdr.bytes[exthdr.bytes_len];
			opt->hdrlen = (n >> 3) - 1;

			//TODO randomize bytes for options
			for(j = sizeof(*opt); j+1 < n; j += 257) {
				exthdr.bytes[exthdr.bytes_len+j] = 0x1e;
				exthdr.bytes[exthdr.bytes_len+j+1] = MIN(n-j-sizeof(*opt), 255);
			}

			if (exthdr.bytes_len == 0) {
				exthdr.ip6nexthdr = IPPROTO_DSTOPTS;
			} else if (exthdr.off_last_nexthdr != MAX_BYTES) {
				exthdr.bytes[exthdr.off_last_nexthdr] = IPPROTO_DSTOPTS;
			}

			exthdr.off_last_nexthdr = exthdr.bytes_len
				+ offsetof(struct ipv6_opt_hdr, nexthdr);
			exthdr.bytes_len += n;
		} else if (!strcmp(argv[i], ARG_RH0)) {
			if (i+1 == argc) {
				print_missing_size(ARG_RH0);
				goto error_out;
			}

			i += 1;
			if (!valid_size(argv[i], MIN_BYTES_RH0, MAX_BYTES_RH0, &n) ||
			    (n-8)%16 != 0) {
				print_invalid_size(ARG_RH0);
				goto error_out;
			}

			if (!force && (flags & (FLAGS_RH | FLAGS_FRAG |
						FLAGS_AH | FLAGS_ESP |
						FLAGS_DEST2))) {
				print_not_rfc8200_compliant();
				goto error_out;
			}
			flags |= FLAGS_RH;

			if (exthdr.bytes_len + n > MAX_BYTES) {
				print_size_overflow(MAX_BYTES);
				goto error_out;
			}

			struct rt0_hdr *rh = (void *)&exthdr.bytes[exthdr.bytes_len];
			rh->rt_hdr.hdrlen = (n >> 3) - 1;
			rh->rt_hdr.type = IPV6_SRCRT_TYPE_0;

			__u16 rh_segs = (n - sizeof(*rh)) / sizeof(rh->addr[0]);
			for(j = 0; j < rh_segs; j++) {
				struct in6_addr rh_addr;
				random_ip6addr(&rh_addr);
				rh->addr[j] = rh_addr;
			}
			rh->rt_hdr.segments_left = rh_segs;

			if (exthdr.bytes_len == 0) {
				exthdr.ip6nexthdr = IPPROTO_ROUTING;
			} else if (exthdr.off_last_nexthdr != MAX_BYTES) {
				exthdr.bytes[exthdr.off_last_nexthdr] = IPPROTO_ROUTING;
			}

			exthdr.off_last_nexthdr = exthdr.bytes_len
				+ offsetof(struct rt0_hdr, rt_hdr.nexthdr);
			exthdr.bytes_len += n;
		} else if (!strcmp(argv[i], ARG_RH2)) {
			if (!force && (flags & (FLAGS_RH | FLAGS_FRAG |
						FLAGS_AH | FLAGS_ESP |
						FLAGS_DEST2))) {
				print_not_rfc8200_compliant();
				goto error_out;
			}
			flags |= FLAGS_RH;

			if (exthdr.bytes_len + 24 > MAX_BYTES) {
				print_size_overflow(MAX_BYTES);
				goto error_out;
			}

			struct rt2_hdr *rh = (void *)&exthdr.bytes[exthdr.bytes_len];
			rh->rt_hdr.hdrlen = 2;
			rh->rt_hdr.type = IPV6_SRCRT_TYPE_2;
			rh->rt_hdr.segments_left = 1;

			struct in6_addr rh_addr;
			random_ip6addr(&rh_addr);
			rh->addr = rh_addr;

			if (exthdr.bytes_len == 0) {
				exthdr.ip6nexthdr = IPPROTO_ROUTING;
			} else if (exthdr.off_last_nexthdr != MAX_BYTES) {
				exthdr.bytes[exthdr.off_last_nexthdr] = IPPROTO_ROUTING;
			}

			exthdr.off_last_nexthdr = exthdr.bytes_len
				+ offsetof(struct rt2_hdr, rt_hdr.nexthdr);
			exthdr.bytes_len += 24;
		} else if (!strcmp(argv[i], ARG_RH3)) {
			if (i+1 == argc) {
				print_missing_size(ARG_RH3);
				goto error_out;
			}

			i += 1;
			if (!valid_size(argv[i], MIN_BYTES_RH3, MAX_BYTES_RH3, &n) ||
			    (n-8)%16 != 0) {
				print_invalid_size(ARG_RH3);
				goto error_out;
			}

			if (!force && (flags & (FLAGS_RH | FLAGS_FRAG |
						FLAGS_AH | FLAGS_ESP |
						FLAGS_DEST2))) {
				print_not_rfc8200_compliant();
				goto error_out;
			}
			flags |= FLAGS_RH;

			if (exthdr.bytes_len + n > MAX_BYTES) {
				print_size_overflow(MAX_BYTES);
				goto error_out;
			}

			struct ipv6_rpl_sr_hdr *rh = (void *)&exthdr.bytes[exthdr.bytes_len];
			rh->hdrlen = (n >> 3) - 1;
			rh->type = IPV6_SRCRT_TYPE_3;

			__u16 rh_segs = (n - sizeof(*rh)) / sizeof(rh->rpl_segaddr[0]);
			for(j = 0; j < rh_segs; j++) {
				struct in6_addr rh_addr;
				random_ip6addr(&rh_addr);
				rh->rpl_segaddr[j] = rh_addr;
			}
			rh->segments_left = rh_segs;

			if (exthdr.bytes_len == 0) {
				exthdr.ip6nexthdr = IPPROTO_ROUTING;
			} else if (exthdr.off_last_nexthdr != MAX_BYTES) {
				exthdr.bytes[exthdr.off_last_nexthdr] = IPPROTO_ROUTING;
			}

			exthdr.off_last_nexthdr = exthdr.bytes_len
				+ offsetof(struct ipv6_rpl_sr_hdr, nexthdr);
			exthdr.bytes_len += n;
		} else if (!strcmp(argv[i], ARG_RH4)) {
			if (i+1 == argc) {
				print_missing_size(ARG_RH4);
				goto error_out;
			}

			i += 1;
			if (!valid_size(argv[i], MIN_BYTES_RH4, MAX_BYTES_RH4, &n) ||
			    (n-8)%16 != 0) {
				print_invalid_size(ARG_RH4);
				goto error_out;
			}

			if (!force && (flags & (FLAGS_RH | FLAGS_FRAG |
						FLAGS_AH | FLAGS_ESP |
						FLAGS_DEST2))) {
				print_not_rfc8200_compliant();
				goto error_out;
			}
			flags |= FLAGS_RH;

			if (exthdr.bytes_len + n > MAX_BYTES) {
				print_size_overflow(MAX_BYTES);
				goto error_out;
			}

			struct ipv6_sr_hdr *rh = (void *)&exthdr.bytes[exthdr.bytes_len];
			rh->hdrlen = (n >> 3) - 1;
			rh->type = IPV6_SRCRT_TYPE_4;

			__u16 rh_segs = (n - sizeof(*rh)) / sizeof(rh->segments[0]);
			for(j = 0; j < rh_segs; j++) {
				struct in6_addr rh_addr;
				random_ip6addr(&rh_addr);
				rh->segments[j] = rh_addr;
			}
			rh->segments_left = rh_segs;
			rh->first_segment = rh_segs - 1;

			if (exthdr.bytes_len == 0) {
				exthdr.ip6nexthdr = IPPROTO_ROUTING;
			} else if (exthdr.off_last_nexthdr != MAX_BYTES) {
				exthdr.bytes[exthdr.off_last_nexthdr] = IPPROTO_ROUTING;
			}

			exthdr.off_last_nexthdr = exthdr.bytes_len
				+ offsetof(struct ipv6_sr_hdr, nexthdr);
			exthdr.bytes_len += n;
		} else if (!strcmp(argv[i], ARG_FRAG_A)) {
			if (!force && (flags & (FLAGS_FRAG | FLAGS_AH |
						FLAGS_ESP | FLAGS_DEST2))) {
				print_not_rfc8200_compliant();
				goto error_out;
			}
			flags |= FLAGS_FRAG;

			if (exthdr.bytes_len + 8 > MAX_BYTES) {
				print_size_overflow(MAX_BYTES);
				goto error_out;
			}

			struct frag_hdr *frag = (void *)&exthdr.bytes[exthdr.bytes_len];
			frag->identification = bpf_htonl(rand());

			if (exthdr.bytes_len == 0) {
				exthdr.ip6nexthdr = IPPROTO_FRAGMENT;
			} else if (exthdr.off_last_nexthdr != MAX_BYTES) {
				exthdr.bytes[exthdr.off_last_nexthdr] = IPPROTO_FRAGMENT;
			}

			exthdr.off_last_nexthdr = exthdr.bytes_len
				+ offsetof(struct frag_hdr, nexthdr);
			exthdr.bytes_len += 8;
		} else if (!strcmp(argv[i], ARG_FRAG_NA)) {
			if (!force && (flags & (FLAGS_FRAG | FLAGS_AH |
						FLAGS_ESP | FLAGS_DEST2))) {
				print_not_rfc8200_compliant();
				goto error_out;
			}
			flags |= FLAGS_FRAG;

			if (exthdr.bytes_len + 8 > MAX_BYTES) {
				print_size_overflow(MAX_BYTES);
				goto error_out;
			}

			struct frag_hdr *frag = (void *)&exthdr.bytes[exthdr.bytes_len];
			frag->identification = bpf_htonl(rand());
			frag->frag_off = bpf_htons(1);

			if (exthdr.bytes_len == 0) {
				exthdr.ip6nexthdr = IPPROTO_FRAGMENT;
			} else if (exthdr.off_last_nexthdr != MAX_BYTES) {
				exthdr.bytes[exthdr.off_last_nexthdr] = IPPROTO_FRAGMENT;
			}

			exthdr.off_last_nexthdr = exthdr.bytes_len
				+ offsetof(struct frag_hdr, nexthdr);
			exthdr.bytes_len += 8;
		} else if (!strcmp(argv[i], ARG_AH)) {
			if (i+1 == argc) {
				print_missing_size(ARG_AH);
				goto error_out;
			}

			i += 1;
			if (!valid_size(argv[i], MIN_BYTES_AH, MAX_BYTES_AH, &n)) {
				print_invalid_size(ARG_AH);
				goto error_out;
			}

			if (!force && (flags & (FLAGS_AH | FLAGS_ESP |
						FLAGS_DEST2))) {
				print_not_rfc8200_compliant();
				goto error_out;
			}
			flags |= FLAGS_AH;

			if (exthdr.bytes_len + n > MAX_BYTES) {
				print_size_overflow(MAX_BYTES);
				goto error_out;
			}

			const __u8 icv[] = { rand(), rand(), rand(), rand() };
			__u16 n_icv = (n >> 2) - 3;

			struct ip_auth_hdr *ah = (void *)&exthdr.bytes[exthdr.bytes_len];
			ah->hdrlen = ((sizeof(*ah) + n_icv * sizeof(icv)) >> 2) - 2;
			ah->spi = bpf_htonl(rand());
			ah->seq_no = bpf_htonl(rand());

			for(j = 0; j < n_icv; j++)
				memcpy(ah->auth_data + j*4, icv, sizeof(icv));

			if (exthdr.bytes_len == 0) {
				exthdr.ip6nexthdr = IPPROTO_AH;
			} else if (exthdr.off_last_nexthdr != MAX_BYTES) {
				exthdr.bytes[exthdr.off_last_nexthdr] = IPPROTO_AH;
			}

			exthdr.off_last_nexthdr = exthdr.bytes_len
				+ offsetof(struct ip_auth_hdr, nexthdr);
			exthdr.bytes_len += n;
		} else if (!strcmp(argv[i], ARG_ESP)) {
			//IPPROTO_ESP
			//TODO set off_last_nexthdr = MAX_BYTES for ESP
/*
if (*len < 16 || (*len % 8) || *len > EH_MAX_BYTES)
	return NULL;

const __u8 esp_enc[] = { 0xde, 0xad, 0xbe, 0xef };
__u16 n_enc = (*len - 8) >> 2;

struct ip_esp_hdr *esp = (void *)exthdr->bytes;
esp->spi = bpf_htonl(0x11223344);
esp->seq_no = bpf_htonl(0x00000001);

*len += bpf_ntohs(ipv6->payload_len) % 8;
for(__u16 i = 0; i < n_enc; i++)
	memcpy(esp->enc_data + i*4, esp_enc, sizeof(esp_enc));
*/
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
