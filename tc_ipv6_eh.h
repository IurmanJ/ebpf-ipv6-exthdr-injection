#ifndef TC_IPV6_EH_H
#define TC_IPV6_EH_H

#define MAP_NAME	eh6_map
#define EH_MAX_BYTES	((255 + 1) << 3)

struct exthdr_t {
	struct bpf_spin_lock lock;
	__u8 type_first_eh;
	__u32 off_last_nxthdr;
	__u32 bytes_len;
#define MIN_BYTES 8
#define MAX_BYTES EH_MAX_BYTES /* Feel free to increase */
	__u8 bytes[MAX_BYTES];
};

#endif
