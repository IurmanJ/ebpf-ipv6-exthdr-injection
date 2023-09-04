#ifndef TC_IPV6_EH_H
#define TC_IPV6_EH_H

#define MAP_NAME	eh6_map
#define EH_MAX_BYTES	((255 + 1) << 3) /* DO NOT MODIFY */

struct exthdr_t {
	struct bpf_spin_lock lock;
	__u8 ip6nexthdr;
	__u32 off_last_nexthdr;
	__u32 bytes_len;
#define MIN_BYTES	8 /* DO NOT MODIFY */
#define MAX_BYTES	EH_MAX_BYTES /* Feel free to modify */
	__u8 bytes[MAX_BYTES];
};

#endif
