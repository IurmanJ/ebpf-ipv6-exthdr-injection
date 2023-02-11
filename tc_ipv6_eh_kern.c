#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <string.h> //memcpy

/* Next Header fields of IPv6 header
 */
#define NEXTHDR_HOP		0	/* Hop-by-hop options header */
#define NEXTHDR_TCP		6	/* TCP segment */
#define NEXTHDR_UDP		17	/* UDP message */
#define NEXTHDR_ROUTING	43	/* Routing header */
#define NEXTHDR_FRAGMENT	44	/* Fragmentation header */
#define NEXTHDR_ESP		50	/* Encapsulating security payload */
#define NEXTHDR_AUTH		51	/* Authentication header */
#define NEXTHDR_ICMP		58	/* ICMPv6 */
#define NEXTHDR_NONE		59	/* No next header */
#define NEXTHDR_DEST		60	/* Destination options header */

#define ETH_P_IPV6		0x86DD

#define TC_ACT_OK		0
#define TC_ACT_SHOT		2

#define MIN(a,b)		((a)<(b) ? (a):(b))
#define EH_MAX_BYTES		((255 + 1) << 3)
#define BPF_F_RECOMPUTE_CSUM	(1ULL << 0)
#define NONE			255

struct exthdr_t {
	__u8 bytes[EH_MAX_BYTES];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exthdr_t);
} percpu_map SEC(".maps");

/* Routing Headers
 */
enum {
	RH_TYPE0 = 0,	/* Source Route (DEPRECATED) [RFC2460][RFC5095] */
	RH_TYPE1,	/* Nimrod (DEPRECATED 2009-05-06) */
	RH_TYPE2,	/* Type 2 Routing Header [RFC6275] */
	RH_TYPE3,	/* RPL Source Route Header [RFC6554] */
	RH_TYPE4,	/* Segment Routing Header (SRH) [RFC8754] */
	__RH_TYPE_MAX
};

/* Fragment types (Fragmentation Header)
 */
enum {
	FRAG_ATOMIC = 0,	/* "More" flag = 0 */
	FRAG_NON_ATOMIC,	/* "More" flag = 1 */
};

char _license[] SEC("license") = "GPL";


static __always_inline struct exthdr_t * prepare_bytes(__u8 eh, __u8 type,
							 __u16 len, __u8 nh)
{
	__u32 idx = 0;
	struct exthdr_t *exthdr = bpf_map_lookup_elem(&percpu_map, &idx);
	if (!exthdr)
		return NULL;

	switch(eh)
	{
		case NEXTHDR_HOP:
		case NEXTHDR_DEST:
			if (len < 8 || (len % 8) || len > EH_MAX_BYTES)
				return NULL;

			exthdr->bytes[0] = nh;
			exthdr->bytes[1] = (len >> 3) - 1;

			for(__u16 i = 2; i + 1 < len; i += 257)
			{
				exthdr->bytes[i] = 0x1e;
				exthdr->bytes[i + 1] = MIN(len - i - 2, 255);
			}
			break;

		case NEXTHDR_FRAGMENT:
			if (len != 8)
				return NULL;

			exthdr->bytes[0] = nh;

			/* TODO
			non-atomic: offset=0 / more=1
			atomic: offset=xxx / more=0
			random identification number?
			*/
			__u16 raw16 = bpf_htons((8 << 3) | type);
			memcpy(&(exthdr->bytes[2]), &raw16, sizeof(__u16));
			__u32 raw32 = bpf_htonl(67634178);
			memcpy(&(exthdr->bytes[4]), &raw32, sizeof(__u32));
			break;

		default:
			return NULL;
	}

	return exthdr;
}

static __always_inline int is_l4_supported(__u8 type)
{
	/* Support for TCP, UDP and ICMP.
	 */
	switch(type)
	{
		case NEXTHDR_TCP:
		case NEXTHDR_UDP:
		case NEXTHDR_ICMP:
			break;

		default:
			return 0;
	}

	return 1;
}

static __always_inline struct ipv6hdr * ipv6_header(struct __sk_buff *skb,
						      __u32 *offset)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	struct ipv6hdr *ipv6;

	*offset = sizeof(*eth) + sizeof(*ipv6);
	if (data + *offset > data_end)
		return NULL;

	if (bpf_ntohs(eth->h_proto) != ETH_P_IPV6)
		return NULL;

	ipv6 = data + sizeof(*eth);
	return ipv6;
}

static __always_inline int egress_eh(struct __sk_buff *skb, __u8 eh,
				      __u8 type, __u16 len)
{
	struct exthdr_t *exthdr;
	struct ipv6hdr *ipv6;
	__u32 off;

	/* Check for pointer overflow (required by the verifier).
	 */
	ipv6 = ipv6_header(skb, &off);
	if (!ipv6)
		return TC_ACT_OK;

	/* Check if EH should be injected with current layer 4.
	 */
	if (!is_l4_supported(ipv6->nexthdr))
		return TC_ACT_OK;

	/* Prepare bytes for current Extension Header buffer.
	 */
	exthdr = prepare_bytes(eh, type, len, ipv6->nexthdr);
	if (!exthdr)
		return TC_ACT_OK;

	/* Make room for the Extension Header to be inserted.
	 */
	if (bpf_skb_adjust_room(skb, len, BPF_ADJ_ROOM_NET, 0))
		return TC_ACT_OK;

	if (bpf_skb_store_bytes(skb, off, &(exthdr->bytes), len, BPF_F_RECOMPUTE_CSUM))
		return TC_ACT_SHOT;

	/* We need to restore/recheck pointers or the verifier will complain,
	 * which is totally understandable after calling bpf_skb_adjust_room or
	 * bpf_skb_store_bytes.
	 */
	ipv6 = ipv6_header(skb, &off);
	if (!ipv6)
		return TC_ACT_SHOT;

	/* Now, we can update the next header and the payload length fields.
	 */
	ipv6->nexthdr = eh;
	ipv6->payload_len = bpf_htons(skb->len - off);

	return TC_ACT_OK;
}

static __always_inline int egress_hop(struct __sk_buff *skb, __u16 len)
{
	return egress_eh(skb, NEXTHDR_HOP, NONE, len);
}

static __always_inline int egress_dest(struct __sk_buff *skb, __u16 len)
{
	return egress_eh(skb, NEXTHDR_DEST, NONE, len);
}

static __always_inline int egress_frag(struct __sk_buff *skb, __u8 type)
{
	return egress_eh(skb, NEXTHDR_FRAGMENT, type, 8);
}

/*static __always_inline int egress_rh(struct __sk_buff *skb, __u8 type, __u16 len)
{
	return egress_eh(skb, NEXTHDR_ROUTING, type, len);
}*/


/*****************************/
/* Hop-by-hop Options Header */
/*****************************/
SEC("tc/egress/hop8") int egress_hop8(struct __sk_buff *skb) {
	return egress_hop(skb, 8);
}
SEC("tc/egress/hop256") int egress_hop256(struct __sk_buff *skb) {
	return egress_hop(skb, 256);
}
SEC("tc/egress/hop512") int egress_hop512(struct __sk_buff *skb) {
	return egress_hop(skb, 512);
}

/******************************/
/* Destination Options Header */
/******************************/
SEC("tc/egress/dest8") int egress_dest8(struct __sk_buff *skb) {
	return egress_dest(skb, 8);
}
SEC("tc/egress/dest16") int egress_dest16(struct __sk_buff *skb) {
	return egress_dest(skb, 16);
}
SEC("tc/egress/dest24") int egress_dest24(struct __sk_buff *skb) {
	return egress_dest(skb, 24);
}
SEC("tc/egress/dest32") int egress_dest32(struct __sk_buff *skb) {
	return egress_dest(skb, 32);
}
SEC("tc/egress/dest40") int egress_dest40(struct __sk_buff *skb) {
	return egress_dest(skb, 40);
}
SEC("tc/egress/dest48") int egress_dest48(struct __sk_buff *skb) {
	return egress_dest(skb, 48);
}
SEC("tc/egress/dest56") int egress_dest56(struct __sk_buff *skb) {
	return egress_dest(skb, 56);
}
SEC("tc/egress/dest64") int egress_dest64(struct __sk_buff *skb) {
	return egress_dest(skb, 64);
}
SEC("tc/egress/dest128") int egress_dest128(struct __sk_buff *skb) {
	return egress_dest(skb, 128);
}
SEC("tc/egress/dest256") int egress_dest256(struct __sk_buff *skb) {
	return egress_dest(skb, 256);
}
SEC("tc/egress/dest512") int egress_dest512(struct __sk_buff *skb) {
	return egress_dest(skb, 512);
}

/************************/
/* Fragmentation Header */
/************************/
SEC("tc/egress/frag_atomic") int egress_fragA(struct __sk_buff *skb) {
	return egress_frag(skb, FRAG_ATOMIC);
}
SEC("tc/egress/frag_nonatomic") int egress_fragNA(struct __sk_buff *skb) {
	return egress_frag(skb, FRAG_NON_ATOMIC);
}

/******************/
/* Routing Header */
/******************/
//TODO max 127 segments possible to grow the size (don't exceed 512 bytes as for other tests: MTU)
