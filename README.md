# IPv6 Extension Headers injection with eBPF

Example of a tc/eBPF program that injects IPv6 Extension Headers.

## Compilation

You need a kernel compiled with `BTF`. Otherwise, it is still possible to compile the program but it gets a little bit more complicated (out of scope here). You can verify it by running:
```
$ grep "CONFIG_DEBUG_INFO_BTF" /boot/config-`uname -r`
```

The output should be as follows:
```
CONFIG_DEBUG_INFO_BTF=y
```

Compile the eBPF program:
```
$ make
```

## Example

Use case: inject a Hop-by-hop (8 bytes) on egress packets

```
# tc qdisc add dev eth0 clsact
# tc filter add dev eth0 egress bpf da obj build/tc_ipv6_eh_kern.o sec egress
```

**IMPORTANT**: you need the iproute2 tool compiled with libbpf support.

You can add more filters (on protocol, src/dst addresses, ports, etc) with tc or inside the program itself (if the latter, a bpf map is probably the way to go).
