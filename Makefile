vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./c/vmlinux.h
