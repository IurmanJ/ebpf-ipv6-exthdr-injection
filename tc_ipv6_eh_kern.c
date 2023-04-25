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
#define NEXTHDR_MOBILITY	135	/* Mobility header */
#define NEXTHDR_HIP		139	/* Host Identity Protocol */
#define NEXTHDR_SHIM6		140	/* Shim6 Protocol */

#define ETH_P_IPV6		0x86DD

#define ICMPV6_ECHO_REQUEST	128

#define TC_ACT_OK		0
#define TC_ACT_SHOT		2

#define MIN(a,b)		((a)<(b) ? (a):(b))
#define EH_MAX_BYTES		((255 + 1) << 3)
#define BPF_F_RECOMPUTE_CSUM	(1ULL << 0)
#define NONE			255

#define JAMES_UDP_SPORT	61344
#define JAMES_UDP_DPORT	33435
#define JAMES_TCP_SPORT	61887
#define JAMES_TCP_DPORT	443
#define JAMES_ICMP6_ID		62144

#define icmp6_identifier	icmp6_dataun.u_echo.identifier

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
	RH_TYPE2,	/* Mobility support [RFC6275] */
	RH_TYPE3,	/* RPL Source Route Header [RFC6554] */
	RH_TYPE4,	/* Segment Routing Header (SRH) [RFC8754] */
	RH_TYPE55 = 55,/* Undefined */
	__RH_TYPE_MAX
};

/* Fragment types (Fragmentation Header)
 */
enum {
	FRAG_ATOMIC = 0,	/* "More" flag = 0 */
	FRAG_NON_ATOMIC,	/* "More" flag = 1 */
};

/* Not included in vmlinux.h (why?)
 */
struct ip_esp_hdr {
	__be32 spi;
	__be32 seq_no;
	__u8 enc_data[];
};
struct rt2_hdr {
	struct ipv6_rt_hdr rt_hdr;
	__be32 res;
	struct in6_addr addr;
};
struct ipv6_rpl_sr_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
	__u8 type;
	__u8 segments_left;
	__be32 flags;
	struct in6_addr addr[];
};

/* Mobility Header (RFC 6275, section 6.1).
 * MH Type 0 (Binding Refresh Request) without Mobility Options.
 */
struct ipv6_mobility_hdr_type0 {
	__u8 nexthdr;
	__u8 hdrlen;
	__u8 mh_type;
	__u8 res;
	__be16 csum;
	__u8 res2;
};

/* Host Identity Protocol Version 2 (RFC 7401, section 5.1).
 * Packet Type 1 (I1 - the HIP Initiator Packet).
 */
struct ipv6_hip_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
	__u8 pkt_type;
	__u8 version;
	__be16 csum;
	__be16 controls;
	struct in6_addr sender_hit;
	struct in6_addr receiver_hit;
	__be16 opt_type;
	__be16 opt_len;
	__u8 gid1;
	__u8 gid2;
	__u8 gid3;
	__u8 gid4;
};

/* Shim6 Protocol (RFC 5533, section 5.1).
 * Shim6 Payload Extension Header.
 */
struct ipv6_shim6_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
	__be16 p_flag;
	__be32 ctx_tag;
};

char _license[] SEC("license") = "GPL";


static __always_inline struct exthdr_t * prepare_bytes(__u8 eh, __u8 type,
							 __u16 *len,
							 struct ipv6hdr *ipv6)
{
	__u32 idx = 0;
	struct exthdr_t *exthdr = bpf_map_lookup_elem(&percpu_map, &idx);
	if (!exthdr)
		return NULL;

	switch(eh)
	{
	case NEXTHDR_HOP:
	case NEXTHDR_DEST:
		if (*len < 8 || (*len % 8) || *len > EH_MAX_BYTES)
			return NULL;

		struct ipv6_opt_hdr *opt = (void *)exthdr->bytes;
		opt->nexthdr = ipv6->nexthdr;
		opt->hdrlen = (*len >> 3) - 1;

		for(__u16 i = 2; i + 1 < *len; i += 257)
		{
			exthdr->bytes[i] = 0x1e;
			exthdr->bytes[i + 1] = MIN(*len - i - 2, 255);
		}
		break;

	case NEXTHDR_FRAGMENT:
		if (*len != 8)
			return NULL;

		struct frag_hdr *frag = (void *)exthdr->bytes;
		frag->nexthdr = ipv6->nexthdr;
		frag->identification = bpf_htonl(0xf88eb466);

		if (type == FRAG_NON_ATOMIC)
			frag->frag_off = bpf_htons(1); // offset=0, more=1
		else
			frag->frag_off = bpf_htons(1448); // offset=1448, more=0
		break;

	case NEXTHDR_ROUTING:
		if (*len < 24 || (*len % 8) || *len > EH_MAX_BYTES)
			return NULL;

		switch(type)
		{
		case RH_TYPE0:
		case RH_TYPE55:
			;
			struct rt0_hdr *rh0 = (void *)exthdr->bytes;
			rh0->rt_hdr.nexthdr = ipv6->nexthdr;
			rh0->rt_hdr.hdrlen = (*len >> 3) - 1;
			rh0->rt_hdr.type = type;

			__u16 n_rh0_segs = (*len - sizeof(*rh0))
						/ sizeof(ipv6->daddr);
			for(__u16 i = 0; i < n_rh0_segs; i++)
				rh0->addr[i] = ipv6->daddr;
			break;

		case RH_TYPE2:
			if (*len != 24)
				return NULL;

			struct rt2_hdr *rh2 = (void *)exthdr->bytes;
			rh2->rt_hdr.nexthdr = ipv6->nexthdr;
			rh2->rt_hdr.hdrlen = 2;
			rh2->rt_hdr.type = type;
			rh2->rt_hdr.segments_left = 1;
			rh2->addr = ipv6->daddr;
			break;

		case RH_TYPE3:
			;
			struct ipv6_rpl_sr_hdr *rpl6 = (void *)exthdr->bytes;
			rpl6->nexthdr = ipv6->nexthdr;
			rpl6->hdrlen = (*len >> 3) - 1;
			rpl6->type = type;

			__u16 n_rpl_seg = (*len - sizeof(*rpl6))
						/ sizeof(ipv6->daddr);
			for(__u16 i = 0; i < n_rpl_seg; i++)
				rpl6->addr[i] = ipv6->daddr;
			break;

		case RH_TYPE4:
			;
			struct ipv6_sr_hdr *seg6 = (void *)exthdr->bytes;
			seg6->nexthdr = ipv6->nexthdr;
			seg6->hdrlen = (*len >> 3) - 1;
			seg6->type = type;

			__u16 n_segments = (*len - sizeof(*seg6))
						/ sizeof(ipv6->daddr);
			for(__u16 i = 0; i < n_segments; i++)
				seg6->segments[i] = ipv6->daddr;
			break;

		default:
			return NULL;
		}
		break;

	case NEXTHDR_AUTH:
		if (*len < 16 || (*len % 8) || *len > 1024)
			return NULL;

		const __u8 ah_icv[] = { 0xde, 0xad, 0xbe, 0xef };
		__u16 n_icv = (*len - 12) >> 2;

		struct ip_auth_hdr *ah = (void *)exthdr->bytes;
		ah->nexthdr = ipv6->nexthdr;
		ah->hdrlen = ((sizeof(*ah) + n_icv * sizeof(ah_icv)) >> 2) - 2;
		ah->spi = bpf_htonl(0x11223344);
		ah->seq_no = bpf_htonl(0x00000001);

		for(__u16 i = 0; i < n_icv; i++)
			memcpy(ah->auth_data + i*4, ah_icv, sizeof(ah_icv));
		break;

	case NEXTHDR_ESP:
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
		break;

	case NEXTHDR_MOBILITY:
		if (type != 0 || *len != 8)
			return NULL;

		struct ipv6_mobility_hdr_type0 *mh = (void *)exthdr->bytes;
		mh->nexthdr = ipv6->nexthdr;
		mh->hdrlen = 0;
		mh->mh_type = 0;
		mh->csum = 0;
		break;

	case NEXTHDR_HIP:
		if (type != 1 || *len != 48)
			return NULL;

		struct ipv6_hip_hdr *hip = (void *)exthdr->bytes;
		hip->nexthdr = ipv6->nexthdr;
		hip->hdrlen = (*len >> 3) - 1;
		hip->pkt_type = 1;
		hip->version = (2 << 4) + 1;
		hip->csum = 0;
		hip->controls = 0;
		hip->sender_hit = ipv6->saddr;
		hip->receiver_hit = ipv6->daddr;
		hip->opt_type = bpf_htons(511);
		hip->opt_len = bpf_htons(4);
		hip->gid1 = 1;
		hip->gid2 = 2;
		hip->gid3 = 3;
		hip->gid4 = 4;
		break;

	case NEXTHDR_SHIM6:
		if (*len != 8)
			return NULL;

		struct ipv6_shim6_hdr *shim = (void *)exthdr->bytes;
		shim->nexthdr = ipv6->nexthdr;
		shim->hdrlen = 0;
		shim->p_flag = bpf_htons(1 << 15);
		shim->ctx_tag = bpf_htonl(123);
		break;

	default:
		return NULL;
	}

	return exthdr;
}

/* Determine when to inject EHs, i.e., based on JAMES configuration.
 * Note: it would be easier to replace the following by a tc filter
 *       (i.e., a command), but it looks like we cannot make the ebpf
 *       program run depending on the result of another tc filter.
 */
static __always_inline __u8 should_inject_eh(struct __sk_buff *skb,
					      __u8 ipv6_nxthdr, __u32 offset)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct icmp6hdr *icmp6;
	struct tcphdr *tcp;
	struct udphdr *udp;

	switch(ipv6_nxthdr)
	{
	case NEXTHDR_TCP:
		if (data + offset + sizeof(*tcp) > data_end)
			return 0;

		tcp = data + offset;
		if (tcp->syn && bpf_ntohs(tcp->source) == JAMES_TCP_SPORT &&
		    bpf_ntohs(tcp->dest) == JAMES_TCP_DPORT)
			return 1;
		break;

	case NEXTHDR_UDP:
		if (data + offset + sizeof(*udp) > data_end)
			return 0;

		udp = data + offset;
		if (bpf_ntohs(udp->source) == JAMES_UDP_SPORT &&
		    bpf_ntohs(udp->dest) == JAMES_UDP_DPORT)
			return 1;
		break;

	case NEXTHDR_ICMP:
		if (data + offset + sizeof(*icmp6) > data_end)
			return 0;

		icmp6 = data + offset;
		if (icmp6->icmp6_type == ICMPV6_ECHO_REQUEST &&
		    bpf_ntohs(icmp6->icmp6_identifier) == JAMES_ICMP6_ID)
			return 1;
		break;

	default:
		break;
	}

	return 0;
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
	if (!should_inject_eh(skb, ipv6->nexthdr, off))
		return TC_ACT_OK;

	/* Prepare bytes for current Extension Header buffer.
	 */
	exthdr = prepare_bytes(eh, type, &len, ipv6);
	if (!exthdr)
		return TC_ACT_OK;

	/* Make room for the Extension Header to be inserted.
	 */
	if (bpf_skb_adjust_room(skb, len, BPF_ADJ_ROOM_NET, 0))
		return TC_ACT_OK;

	if (bpf_skb_store_bytes(skb, off, &(exthdr->bytes), len,
				 BPF_F_RECOMPUTE_CSUM))
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

static __always_inline int egress_rh(struct __sk_buff *skb, __u8 rht, __u16 len)
{
	return egress_eh(skb, NEXTHDR_ROUTING, rht, len);
}

static __always_inline int egress_ah(struct __sk_buff *skb, __u16 len)
{
	return egress_eh(skb, NEXTHDR_AUTH, NONE, len);
}

static __always_inline int egress_esp(struct __sk_buff *skb, __u16 len)
{
	return egress_eh(skb, NEXTHDR_ESP, NONE, len);
}


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
// Routing Type 0
SEC("tc/egress/rh0-24") int egress_rh0_1seg(struct __sk_buff *skb) {
	return egress_rh(skb, RH_TYPE0, 24);
}
SEC("tc/egress/rh0-680") int egress_rh0_42seg(struct __sk_buff *skb) {
	return egress_rh(skb, RH_TYPE0, 680);
}
SEC("tc/egress/rh0-1368") int egress_rh0_85seg(struct __sk_buff *skb) {
	return egress_rh(skb, RH_TYPE0, 1368);
}

// Routing Type 2 (fixed size)
SEC("tc/egress/rh2") int egress_rh2(struct __sk_buff *skb) {
	return egress_rh(skb, RH_TYPE2, 24);
}

// Routing Type 3
SEC("tc/egress/rh3-24") int egress_rh3_1seg(struct __sk_buff *skb) {
	return egress_rh(skb, RH_TYPE3, 24);
}
SEC("tc/egress/rh3-680") int egress_rh3_42seg(struct __sk_buff *skb) {
	return egress_rh(skb, RH_TYPE3, 680);
}
SEC("tc/egress/rh3-1368") int egress_rh3_85seg(struct __sk_buff *skb) {
	return egress_rh(skb, RH_TYPE3, 1368);
}

// Routing Type 4
SEC("tc/egress/rh4-24") int egress_rh4_1seg(struct __sk_buff *skb) {
	return egress_rh(skb, RH_TYPE4, 24);
}
SEC("tc/egress/rh4-680") int egress_rh4_42seg(struct __sk_buff *skb) {
	return egress_rh(skb, RH_TYPE4, 680);
}
SEC("tc/egress/rh4-1368") int egress_rh4_85seg(struct __sk_buff *skb) {
	return egress_rh(skb, RH_TYPE4, 1368);
}

// Undefined Routing Type 55 (similar to Routing Type 0 by default)
SEC("tc/egress/rh55-24") int egress_rh55_1seg(struct __sk_buff *skb) {
	return egress_rh(skb, RH_TYPE55, 24);
}
SEC("tc/egress/rh55-680") int egress_rh55_42seg(struct __sk_buff *skb) {
	return egress_rh(skb, RH_TYPE55, 680);
}
SEC("tc/egress/rh55-1368") int egress_rh55_85seg(struct __sk_buff *skb) {
	return egress_rh(skb, RH_TYPE55, 1368);
}

/*********/
/* IPSec */
/*********/
// Authentication Header (AH)
SEC("tc/egress/ah-16") int egress_ah_min(struct __sk_buff *skb) {
	return egress_ah(skb, 16);
}
SEC("tc/egress/ah-512") int egress_ah_medium(struct __sk_buff *skb) {
	return egress_ah(skb, 512);
}
SEC("tc/egress/ah-1024") int egress_ah_max(struct __sk_buff *skb) {
	return egress_ah(skb, 1024);
}

// Encapsulating Security Payload (ESP)
SEC("tc/egress/esp-16") int egress_esp_min(struct __sk_buff *skb) {
	return egress_esp(skb, 16);
}
SEC("tc/egress/esp-512") int egress_esp_medium(struct __sk_buff *skb) {
	return egress_esp(skb, 512);
}
SEC("tc/egress/esp-1024") int egress_esp_big(struct __sk_buff *skb) {
	return egress_esp(skb, 1024);
}

/*******************/
/* Mobility Header */
/*******************/
// MH Type 0 without Mobility Options
SEC("tc/egress/mh") int egress_mh(struct __sk_buff *skb) {
	return egress_eh(skb, NEXTHDR_MOBILITY, 0, 8);
}

/**************************/
/* Host Identity Protocol */
/**************************/
// Packet Type 1
SEC("tc/egress/hip") int egress_hip(struct __sk_buff *skb) {
	return egress_eh(skb, NEXTHDR_HIP, 1, 48);
}

/******************/
/* Shim6 Protocol */
/******************/
// Shim6 Payload Extension Header
SEC("tc/egress/shim6") int egress_shim6(struct __sk_buff *skb) {
	return egress_eh(skb, NEXTHDR_SHIM6, NONE, 8);
}
