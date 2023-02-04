#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IPV6		0x86DD

#define NEXTHDR_HOP		0
#define NEXTHDR_TCP		6
#define NEXTHDR_UDP		17
#define NEXTHDR_ICMP		58
#define NEXTHDR_DEST		60

#define BPF_F_RECOMPUTE_CSUM	(1ULL << 0)

#define TC_ACT_OK		0
#define TC_ACT_SHOT		2

char _license[] SEC("license") = "GPL";


static __always_inline int egress_eh(struct __sk_buff *skb, __u8 nh, __u16 len)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	struct ipv6hdr *ipv6;
	__u8 bytes[len];
	__u32 off;

	/* Initialize EH Options' payload to 0's, although we might not do this
	 * if we wanted direct bytes randomization.
	 */
	for(__u16 i = 0; i < len; i++)
		bytes[i] = 0;

	/* Pointer overflow check required by the verifier.
	 */
	off = sizeof(*eth) + sizeof(*ipv6);
	if (data + off > data_end)
		return TC_ACT_OK;

	/* Make sure it is an IPv6 packet.
	 */
	if (bpf_ntohs(eth->h_proto) != ETH_P_IPV6)
		return TC_ACT_OK;

	/* Currently, we inject EHs only with TCP, UDP and ICMP.
	 */
	ipv6 = data + sizeof(*eth);
	switch(ipv6->nexthdr)
	{
		case NEXTHDR_TCP:
		case NEXTHDR_UDP:
		case NEXTHDR_ICMP:
			break;

		default:
			return TC_ACT_OK;
	}

	bytes[0] = ipv6->nexthdr;
	bytes[1] = (len >> 3) - 1;
	//TODO case when multiple options
	bytes[2] = 0x1e;
	bytes[3] = len - 4;

	if (bpf_skb_adjust_room(skb, len, BPF_ADJ_ROOM_NET, 0))
		return TC_ACT_OK;

	if (bpf_skb_store_bytes(skb, off, bytes, len, BPF_F_RECOMPUTE_CSUM))
		return TC_ACT_SHOT;

	/* We need to restore/recheck pointers or the verifier will complain,
	 * which is totally understandable after calling bpf_skb_adjust_room or
	 * bpf_skb_store_bytes.
	 */
	data_end = (void *)(long)skb->data_end;
	data = (void *)(long)skb->data;
	if (data + off > data_end)
		return TC_ACT_SHOT;

	/* Now, we can update the next header and the payload length fields.
	 */
	ipv6 = data + sizeof(*eth);
	ipv6->nexthdr = nh;
	ipv6->payload_len = bpf_htons(skb->len - off);

	return TC_ACT_OK;
}


/*********************/
/* Hop-by-hop Option */
/*********************/
SEC("tc/egress/hbh8") int egress_hbh8(struct __sk_buff *skb) {
	return egress_eh(skb, NEXTHDR_HOP, 8);
}
SEC("tc/egress/hbh256") int egress_hbh256(struct __sk_buff *skb) {
	return egress_eh(skb, NEXTHDR_HOP, 256);
}
//TODO 512
/*tc_ipv6_eh_kern.c:35:12: error: Looks like the BPF stack limit of 512 bytes is exceeded. Please move large on stack variables into BPF per-cpu array map.*/

// DO, HBH and RHs max size is 2048 bytes (2048/8 - 1 = 255)

/**********************/
/* Destination Option */
/**********************/
SEC("tc/egress/do8") int egress_do8(struct __sk_buff *skb) {
	return egress_eh(skb, NEXTHDR_DEST, 8);
}
SEC("tc/egress/do16") int egress_do16(struct __sk_buff *skb) {
	return egress_eh(skb, NEXTHDR_DEST, 16);
}
SEC("tc/egress/do24") int egress_do24(struct __sk_buff *skb) {
	return egress_eh(skb, NEXTHDR_DEST, 24);
}
SEC("tc/egress/do32") int egress_do32(struct __sk_buff *skb) {
	return egress_eh(skb, NEXTHDR_DEST, 32);
}
SEC("tc/egress/do40") int egress_do40(struct __sk_buff *skb) {
	return egress_eh(skb, NEXTHDR_DEST, 40);
}
SEC("tc/egress/do48") int egress_do48(struct __sk_buff *skb) {
	return egress_eh(skb, NEXTHDR_DEST, 48);
}
SEC("tc/egress/do56") int egress_do56(struct __sk_buff *skb) {
	return egress_eh(skb, NEXTHDR_DEST, 56);
}
SEC("tc/egress/do64") int egress_do64(struct __sk_buff *skb) {
	return egress_eh(skb, NEXTHDR_DEST, 64);
}
SEC("tc/egress/do128") int egress_do128(struct __sk_buff *skb) {
	return egress_eh(skb, NEXTHDR_DEST, 128);
}
SEC("tc/egress/do256") int egress_do256(struct __sk_buff *skb) {
	return egress_eh(skb, NEXTHDR_DEST, 256);
}
//TODO 512 (, 1024, 2048?)
