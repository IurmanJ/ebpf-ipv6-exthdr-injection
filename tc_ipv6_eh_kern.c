#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "tc_ipv6_eh.h"

#define ETH_P_IPV6		0x86DD
#define ICMPV6_ECHO_REQUEST	128
#define NEXTHDR_TCP		6
#define NEXTHDR_UDP		17
#define NEXTHDR_ICMP		58

#define TC_ACT_OK		0
#define TC_ACT_SHOT		2

#define UDP_DPORT		443
#define TCP_DPORT		443

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exthdr_t);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_NAME SEC(".maps");

char _license[] SEC("license") = "GPL";


/* Custom filter based on layer 4, matches on either:
 *  - TCP:	SYN, dport=TCP_DPORT
 *  - UDP:	dport=UDP_DPORT
 *  - ICMPv6:	type=EchoRequest
 *
 * --> Feel free to modify it according to your needs.
 *
 * Note: it would be easier to replace the following by a tc filter
 *       (i.e., a command), but it looks like we cannot make the ebpf
 *       program run depending on the result of another tc filter (?).
 */
static __always_inline __u8 pass_custom_filter(
	struct __sk_buff *skb, __u8 ipv6_nxthdr, __u32 offset)
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
		if (tcp->syn && bpf_ntohs(tcp->dest) == TCP_DPORT)
			return 1;
		break;

	case NEXTHDR_UDP:
		if (data + offset + sizeof(*udp) > data_end)
			return 0;

		udp = data + offset;
		if (bpf_ntohs(udp->dest) == UDP_DPORT)
			return 1;
		break;

	case NEXTHDR_ICMP:
		if (data + offset + sizeof(*icmp6) > data_end)
			return 0;

		icmp6 = data + offset;
		if (icmp6->icmp6_type == ICMPV6_ECHO_REQUEST)
			return 1;
		break;

	default:
		break;
	}

	return 0;
}

static __always_inline struct ipv6hdr * ipv6_header(
	struct __sk_buff *skb, __u32 *offset)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6;

	*offset = sizeof(*eth) + sizeof(*ip6);
	if (data + *offset > data_end)
		return NULL;

	if (bpf_ntohs(eth->h_proto) != ETH_P_IPV6)
		return NULL;

	ip6 = data + sizeof(*eth);
	return ip6;
}

SEC("egress")
int egress_eh6(struct __sk_buff *skb)
{
	__u32 off, bytes_len, off_last_nexthdr, idx = 0, mtu = 0;
	struct exthdr_t *exthdr;
	struct ipv6hdr *ip6;
	__u8 ip6nexthdr;

	/* Check for IPv6, and pointer overflow (required by the verifier).
	 */
	ip6 = ipv6_header(skb, &off);
	if (!ip6)
		return TC_ACT_OK;

	/* Custom filter applied per packet.
	 */
	//if (!pass_custom_filter(skb, ip6->nexthdr, off))
	//	return TC_ACT_OK;

	/* Retrieve the map element we need.
	 */
	exthdr = bpf_map_lookup_elem(&eh6_map, &idx);
	if (!exthdr)
		return TC_ACT_OK;

	/* Hold the lock to read data.
	 *
	 * Note: we can't hold the lock and call a bpf_* function, so we
	 *       either need to copy bytes on the stack (too big and too slow)
	 *	 or read them without the lock (not good, but what can we do?).
	 */
	//bpf_spin_lock(&exthdr->lock);

	bytes_len = exthdr->bytes_len;
	if (bytes_len < 8 || bytes_len > MAX_BYTES ||
	    bpf_check_mtu(skb, skb->ifindex, &mtu, bytes_len, 0)) {
		//bpf_spin_unlock(&exthdr->lock);
		return TC_ACT_OK;
	}

	off_last_nexthdr = exthdr->off_last_nexthdr;

	ip6nexthdr = ip6->nexthdr;
	ip6->nexthdr = exthdr->ip6nexthdr;
	ip6->payload_len = bpf_htons(bpf_ntohs(ip6->payload_len) + bytes_len);

	/* Make room for new bytes and insert them.
	 */
	if (bpf_skb_adjust_room(skb, bytes_len, BPF_ADJ_ROOM_NET, 0))
		return TC_ACT_SHOT;

	if (bpf_skb_store_bytes(skb, off, exthdr->bytes, bytes_len, 0))
		return TC_ACT_SHOT;

	//bpf_spin_unlock(&exthdr->lock);
	/* ----------------------------------------------------------------- */

	/* Update last Extension Header's nexthdr field.
	 */
	if (off_last_nexthdr < MAX_BYTES &&
	    bpf_skb_store_bytes(skb, off + off_last_nexthdr, &ip6nexthdr,
				sizeof(ip6nexthdr), 0))
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}
