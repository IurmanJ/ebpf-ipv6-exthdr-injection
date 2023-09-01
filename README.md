# IPv6 Extension Headers injection with eBPF

This tc/eBPF program injects IPv6 Extension Headers, either a single one or a
stack of Extension Headers.

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

### Used environment

- Linux kernel version 5.15.0-82-generic
- Iproute2 version iproute2-5.15.0 (with libbpf 0.5.0)
- Clang version 14.0.0

Some oldest kernel versions should be fine too. However, pay attention to oldest clang versions. You may encounter some verifier errors during bpf program loading (e.g., with clang 10).

## Example

Use case: inject a Hop-by-hop (8 bytes) on egress packets

```
# tc qdisc add dev eth0 clsact
# tc filter add dev eth0 egress bpf da obj build/tc_ipv6_eh_kern.o sec egress
# LD_LIBRARY_PATH=deps/libbpf/src ./build/tc_ipv6_eh_user.o --hbh 8
```

**IMPORTANT**: you need the iproute2 tool compiled with libbpf support.
