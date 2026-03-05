package correlator

import "golang.org/x/sys/unix"

const (
	EventOpen    uint8 = 1
	EventConnect uint8 = 2
	EventExec    uint8 = 3

	AF_INET  = unix.AF_INET
	AF_INET6 = unix.AF_INET6
)

type Event struct {
	Type      uint8
	_         [3]byte
	Pid       int32
	Tgid      int32
	_         [4]byte
	Timestamp uint64
	Command   [32]byte

	Fname [64]byte

	ConFamily uint16
	ConPort   uint16
	Ipv4Addr  [4]byte
	Ipv6Addr  [16]byte

	Ppid           int32
	Gppid          int32
	ParentCommand  [32]byte
	GParentCommand [32]byte
}
