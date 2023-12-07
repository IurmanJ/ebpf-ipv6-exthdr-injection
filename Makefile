MAKEFILE_DIR=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CLANG=clang
GCC=gcc

all: deps build
.PHONY: all

deps: apt-packages libbpf bpftool
.PHONY: deps

apt-packages:
	sudo apt-get -q update && sudo apt-get install --no-install-recommends -q -y \
		libelf-dev \
		llvm \
		clang \
		libcap-dev \
		binutils-dev \
		git
.PHONY: install-deps

libbpf:
	if [ ! -e deps/libbpf ] ; then git clone --recursive --depth 1 https://github.com/libbpf/libbpf ./deps/libbpf ; fi
	$(MAKE) -j -C deps/libbpf/src/ DESTDIR="$(MAKEFILE_DIR)/build" install
.PHONY: libbpf

bpftool:
	if [ ! -e deps/bpftool ] ; then git clone --recursive --depth 1 https://github.com/libbpf/bpftool ./deps/bpftool ; fi
	$(MAKE) -j -C deps/bpftool/src/
.PHONY: bpftool

build:
	uname -a
	mkdir -p $@
	deps/bpftool/src/bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@/vmlinux.h
	$(CLANG) -g -O2 -Wall -Wextra -target bpf -D__TARGET_ARCH_x86_64 -I $@ -I $@/usr/include -c tc_ipv6_eh_kern.c -o $@/tc_ipv6_eh_kern.o
	$(GCC) tc_ipv6_eh_user.c -I $@/usr/include -L $@/usr/lib64 -lbpf -o $@/tc_ipv6_eh_user.o
.PHONY: build

clean:
	rm -rf build deps
.PHONY: clean
