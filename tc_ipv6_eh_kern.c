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


static __always_inline int egress_eh(struct __sk_buff *skb, __u8 eh_type, __u8 bytes[], __u16 bytes_len)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	struct ipv6hdr *ipv6h;
	__u32 eh_offset;
	int ret;

	if (data + sizeof(*eth) > data_end)
		return TC_ACT_OK;

	if (bpf_ntohs(eth->h_proto) != ETH_P_IPV6)
		return TC_ACT_OK;

	eh_offset = sizeof(*eth) + sizeof(*ipv6h);
	if (data + eh_offset > data_end)
		return TC_ACT_OK;

	ipv6h = data + sizeof(*eth);
	bytes[0] = ipv6h->nexthdr;
	bytes[1] = (bytes_len >> 3) - 1;

	switch(ipv6h->nexthdr)
	{
		case NEXTHDR_TCP:
		case NEXTHDR_UDP:
		case NEXTHDR_ICMP:
			break;

		default:
			return TC_ACT_OK;
	}

	ret = bpf_skb_adjust_room(skb, bytes_len, BPF_ADJ_ROOM_NET, 0);
	if (ret)
		return TC_ACT_OK;

	ret = bpf_skb_store_bytes(skb, eh_offset, bytes, bytes_len, BPF_F_RECOMPUTE_CSUM);
	if (ret)
		return TC_ACT_SHOT;

	/* We need to restore/recheck pointers or the verifier will complain,
	 * which is totally understandable after calling bpf_skb_adjust_room or
	 * bpf_skb_store_bytes
	 */
	data_end = (void *)(long)skb->data_end;
	data = (void *)(long)skb->data;
	if (data + eh_offset > data_end)
		return TC_ACT_SHOT;

	ipv6h = data + sizeof(*eth);
	ipv6h->nexthdr = eh_type;
	ipv6h->payload_len = bpf_htons(skb->len - sizeof(*eth) - sizeof(*ipv6h));

	return TC_ACT_OK;
}

// DO, HBH and RHs max size is 2048 bytes (2048/8 - 1 = 255)
// DO: 8, 16, 24, 32, 40, 48, 56, 64, 128, 256, 512 (, 1024, 2048 ?)
// HBH: 8, 256, 512
// RH: add segments to grow the size (only types (0, 1,) 2, 3, 4 ?)
// Fragment: fixed size
// ESP and AH: grow the size?
//test other EHs? see https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#extension-header

SEC("tc/egress/do8")
int egress_do8(struct __sk_buff *skb)
{
	__u8 bytes[] = { 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00 };
	return egress_eh(skb, NEXTHDR_DEST, bytes, sizeof(bytes));
}

SEC("tc/egress/hbh8")
int egress_hbh8(struct __sk_buff *skb)
{
	__u8 bytes[] = { 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00 };
	return egress_eh(skb, NEXTHDR_HOP, bytes, sizeof(bytes));
}

SEC("tc/egress/hbh16")
int egress_hbh16(struct __sk_buff *skb)
{
	__u8 bytes[] = { 0x00, 0x00, 0x1e, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	return egress_eh(skb, NEXTHDR_HOP, bytes, sizeof(bytes));
}

char _license[] SEC("license") = "GPL";
