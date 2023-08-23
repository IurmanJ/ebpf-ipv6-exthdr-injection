#ifndef TC_IPV6_EH_H
#define TC_IPV6_EH_H

#define MAP_NAME	eh6_map
#define EH_MAX_BYTES	((255 + 1) << 3)
#define MAX_BYTES	EH_MAX_BYTES /* Feel free to increase */

struct exthdr_t {
	struct bpf_spin_lock lock;
	__u8 type_first_eh;
	__u16 off_last_nxthdr;
	__u16 bytes_len;
	__u8 bytes[MAX_BYTES];
};

#endif
