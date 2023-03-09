MAKEFILE_DIR=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CLANG=clang

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
	$(MAKE) -j -C deps/libbpf/src/ BUILD_STATIC_ONLY=y DESTDIR="$(MAKEFILE_DIR)/build" INCLUDEDIR= LIBDIR= UAPIDIR= install
.PHONY: libbpf

bpftool:
	if [ ! -e deps/bpftool ] ; then git clone --recursive --depth 1 https://github.com/libbpf/bpftool ./deps/bpftool ; fi
	$(MAKE) -j -C deps/bpftool/src/
.PHONY: bpftool

build:
	uname -a
	mkdir -p $@
	deps/bpftool/src/bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@/vmlinux.h
	$(CLANG) -g -O2 -Wall -Wextra -target bpf -D__TARGET_ARCH_x86_64 -I $@ -c tc_ipv6_eh_kern.c -o $@/tc_ipv6_eh_kern.o
.PHONY: build

clean:
	rm -rf build deps
.PHONY: clean
