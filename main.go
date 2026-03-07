package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ItsMonish/barbwire/internal/config"
	"github.com/ItsMonish/barbwire/internal/correlator"
	"github.com/ItsMonish/barbwire/internal/types"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -tags linux -cflags "-Wno-missing-declarations" correlator c/correlator.bpf.c

func main() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	conf, err := config.LoadConfig("config.yml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	_ = conf.CorrelationWindowSeconds

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Error removing memlock: %v", err)
	}

	objs := correlatorObjects{}
	if err := loadCorrelatorObjects(&objs, nil); err != nil {
		log.Fatalf("Error in loading eBPF objects: %v", err)
	}
	defer objs.Close()

	tpOpen, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.RecordOpen, nil)
	if err != nil {
		log.Fatalf("Error attaching to open: %v", err)
	}
	defer tpOpen.Close()

	tpConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.RecordConnect, nil)
	if err != nil {
		log.Fatalf("Error attaching to connect: %v", err)
	}
	defer tpConnect.Close()

	tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.RecordExec, nil)
	if err != nil {
		log.Fatalf("Error attaching to exec: %v", err)
	}
	defer tpExec.Close()

	rbReader, err := ringbuf.NewReader(objs.RingBuffer)
	if err != nil {
		log.Fatalf("Error opening ring buffer: %v", err)
	}
	defer rbReader.Close()

	log.Println("Barbwire running... Press Ctrl+C to exit")

	go func() {
		<-stop
		rbReader.Close()
	}()

	corr := correlator.NewCorrelator(conf)

	for {
		record, err := rbReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Ring buffer closed. Shutting down...")
				return
			}
			log.Printf("Error reading from ring buffer: %v", err)
			continue
		}

		var ev types.Event
		err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev)
		if err != nil {
			log.Printf("Error parsing ring buffer record: %v", err)
			continue
		}

		corr.HandleEvent(ev)
	}
}
