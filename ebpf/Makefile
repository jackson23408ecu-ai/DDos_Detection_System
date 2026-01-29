CLANG ?= clang

CFLAGS_BPF  := -O2 -g -target bpf -D__TARGET_ARCH_x86 \
               -I. \
               -I/usr/local/include/libbpf

CFLAGS_USER := -O2 -g -Wall
LIBS_USER   := -lbpf -lelf -lz

VMLINUX_H := vmlinux.h

all: xdp_flow_kern.o xdp_flow_user

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

xdp_flow_kern.o: xdp_flow_kern.c $(VMLINUX_H)
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

xdp_flow_user: xdp_flow_user.c
	$(CLANG) $(CFLAGS_USER) $< -o $@ \
	  -I/usr/local/include/libbpf \
	  -L/usr/local/libbpf/src -Wl,-rpath,/usr/local/libbpf/src \
	  $(LIBS_USER)

clean:
	rm -f xdp_flow_kern.o xdp_flow_user $(VMLINUX_H)

.PHONY: all clean
