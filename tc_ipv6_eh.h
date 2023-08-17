#ifndef TC_IPV6_EH_H
#define TC_IPV6_EH_H

#define MAP_NAME	eh6_map
#define EH_MAX_BYTES	((255 + 1) << 3)

struct exthdr_t {
	struct bpf_spin_lock lock;
	__u8 enabled;
	__u8 bytes[EH_MAX_BYTES];
};

#endif
