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

Here is the output of the *help* section:

```
Usage: ./build/tc_ipv6_eh_user.o { --disable | --enable [ --force ] EXTHDR [ EXTHDR ... EXTHDR ] }

EXTHDR := { --hbh 8..2048 | --dest 8..2048 | --rh0 24..2040 | --rh2 | --rh3 24..2040 | --rh4 24..2040 | --fragA | --fragNA | --ah 16..1024 | --esp 16..2048 }

If a size is required, it MUST be an 8-octet multiple.
Routing Header sizes minus 8 MUST be 16-octet multiples.

Accepted chaining order, as per RFC8200 sec4.1:
 - Hop-by-Hop Options header
 - Destination Options header
 - Routing header
 - Fragment header
 - Authentication header
 - Encapsulating Security Payload header
 - Destination Options header

```

## Notes

If you encounter issues with checksum verifications (or any related problem where a packet magically disappears somewhere on the path), you may need to **disable TX checksum offloading** (`sudo ethtool -K eth0 tx off`) where IPv6 EHs are injected.
