#ifndef TC_IPV6_EH_H
#define TC_IPV6_EH_H

#define MAP_NAME	eh6_map

struct exthdr_t {
	struct bpf_spin_lock lock;
	__u8 ip6nexthdr;
	__u32 off_last_nexthdr;
	__u32 bytes_len;
#define MAX_BYTES	2048 /* Feel free to increase if needed */
	__u8 bytes[MAX_BYTES];
};

#endif
