# IPv6 Extension Headers injection with eBPF

This tc/eBPF program injects one or several IPv6 Extension Headers per packet on egress traffic.

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

Note: recent distros have kernels with `BTF` enabled by default.

### Used environment

- Linux kernel version 5.15.0-82-generic
- Iproute2 version iproute2-5.15.0 (with libbpf 0.5.0)
- Clang version 14.0.0

Some oldest kernel versions should be fine too. However, pay attention to oldest clang versions. You may encounter some verifier errors when loading the bpf program with tc (e.g., with clang 10).

Note: for instance, the above environment corresponds to Ubuntu 22.04.3 LTS (Jammy) and would work by default.

## Example

Use case: inject a Hop-by-hop Options (8 bytes) and a Destination Options (16 bytes) on egress packets (interface "eth0").

```
# tc qdisc add dev eth0 clsact
# tc filter add dev eth0 egress protocol ipv6 prio 10 bpf da obj build/tc_ipv6_eh_kern.o sec egress
# ./build/tc_ipv6_eh_user.o --enable --hbh 8 --dest 16
```

**IMPORTANT**: you need the iproute2 tool compiled with libbpf support.

Note: You may need to set `LD_LIBRARY_PATH` in order to run the user program:

```
# LD_LIBRARY_PATH=deps/libbpf/src ./build/tc_ipv6_eh_user.o --enable --hbh 8 --dest 16
```
