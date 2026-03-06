vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./c/vmlinux.h

generate: vmlinux
	go generate

run: generate
	sudo go run .

clean:
	rm -f ./c/vmlinux.h ./correlator_bpfe?.o ./correlator_bpfe?.go
