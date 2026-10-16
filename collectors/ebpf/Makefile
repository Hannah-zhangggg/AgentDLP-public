.RECIPEPREFIX := >

CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

BPF_OBJECT := connect_observer.bpf.o
USER_BINARY := connect_observer

BPF_CFLAGS := \
	-g \
	-O2 \
	-fno-vectorize \
	-fno-slp-vectorize \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-I.

USER_CFLAGS := \
	-g \
	-O2 \
	-Wall \
	-Wextra \
	$(shell pkg-config --cflags libbpf)

USER_LIBS := \
	$(shell pkg-config --libs libbpf) \
	-lelf \
	-lz

.PHONY: all inspect clean

all: $(BPF_OBJECT) $(USER_BINARY)

vmlinux.h: $(VMLINUX_BTF)
>test -r "$<"
>$(BPFTOOL) btf dump file "$<" format c > "$@.tmp"
>mv "$@.tmp" "$@"

$(BPF_OBJECT): connect_observer.bpf.c connect_observer.h vmlinux.h
>$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BINARY): connect_observer.c connect_observer.h
>$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LIBS)

inspect: all
>file $(BPF_OBJECT) $(USER_BINARY)
>llvm-objdump -h $(BPF_OBJECT)
>readelf -S $(BPF_OBJECT)
>ldd $(USER_BINARY)

clean:
>$(RM) $(BPF_OBJECT) $(USER_BINARY) vmlinux.h vmlinux.h.tmp
