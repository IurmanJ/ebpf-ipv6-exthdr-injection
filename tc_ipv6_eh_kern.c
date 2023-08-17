#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "tc_ipv6_eh.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exthdr_t);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} MAP_NAME SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("egress")
int egress_eh6(struct __sk_buff *skb)
{
	struct exthdr_t *exthdr;
	__u32 idx = 0;
	__u8 enabled;

	exthdr = bpf_map_lookup_elem(&eh6_map, &idx);
	if (!exthdr)
		return 0;

	bpf_spin_lock(&exthdr->lock);
	enabled = exthdr->enabled;
	bpf_spin_unlock(&exthdr->lock);

	bpf_printk("enabled? %u\n", enabled);
	return 0;
}
