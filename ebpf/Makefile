CLANG ?= clang

CFLAGS_BPF  := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I.
CFLAGS_USER := -O2 -g -Wall
LIBS_USER   := -lbpf -lelf -lz

VMLINUX_H := vmlinux.h

all: xdp_flow_kern.o xdp_flow_user

# 自动生成 vmlinux.h（CO-RE 需要）
# 如果你没装 bpftool：sudo apt install -y bpftool
$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

# 编译 eBPF（CO-RE：只依赖 vmlinux.h + libbpf 头，不引入内核源码树头文件）
xdp_flow_kern.o: xdp_flow_kern.c $(VMLINUX_H)
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

# 编译用户态（libbpf 加载 + ringbuf 读取）
xdp_flow_user: xdp_flow_user.c
	$(CLANG) $(CFLAGS_USER) $< -o $@ \
	  -I/usr/local/include -L/usr/local//libbpf/src -Wl,-rpath,/usr/local//libbpf/src \
	  -lbpf -lelf -lz


clean:
	rm -f xdp_flow_kern.o xdp_flow_user $(VMLINUX_H)

.PHONY: all clean
