package correlator

import (
	"bytes"
	"fmt"
	"math/bits"
	"net"
	"time"

	"github.com/ItsMonish/barbwire/internal/config"
)

func NewCorrelator(conf *config.Config) *Correlator {
	c := &Correlator{
		recentOpens: make(map[int32][]OpenEntry),
		lineage:     make(map[int32]LineageEntry),
		window:      time.Duration(conf.CorrelationWindowSeconds) * time.Second,
	}

	return c
}

func (c *Correlator) HandleEvent(ev Event) {
	switch ev.Type {
	case EventOpen:
		c.handleOpen(ev)
	case EventConnect:
		c.handleConnect(ev)
	case EventExec:
		c.handleExec(ev)
	}
}

func (c *Correlator) handleOpen(ev Event) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry := OpenEntry{
		timestamp: time.Now(),
		fname:     trimNull(ev.Fname[:]),
	}

	c.recentOpens[ev.Pid] = append(c.recentOpens[ev.Pid], entry)
}

func (c *Correlator) handleExec(ev Event) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lineage[ev.Pid] = LineageEntry{
		ppid:        ev.Ppid,
		gppid:       ev.Gppid,
		parentComm:  trimNull(ev.ParentCommand[:]),
		gparentComm: trimNull(ev.GParentCommand[:]),
	}
}

func (c *Correlator) handleConnect(ev Event) {
	if ev.ConFamily != AF_INET && ev.ConFamily != AF_INET6 {
		return
	}

	c.mu.Lock()
	opens, ok := c.recentOpens[ev.Pid]
	lineage, hasLineage := c.lineage[ev.Pid]
	c.mu.Unlock()

	if !ok {
		return
	}

	now := time.Now()
	for _, open := range opens {
		fmt.Printf("Looking at %d\n", ev.Pid)
		if now.Sub(open.timestamp) < c.window {
			continue
		}

		command := trimNull(ev.Command[:])
		addr, port := resolvPort(ev)

		fmt.Printf("\n┌─ barbwire alert — PID %-6d ─────────────\n", ev.Pid)
		fmt.Printf("│  command  : %s\n", command)
		fmt.Printf("│  file     : %s\n", open.fname)
		fmt.Printf("│  connect  : %s:%d\n", addr, port)

		if hasLineage {
			fmt.Printf("│  parent   : %s (pid %d)\n", lineage.parentComm, lineage.ppid)
			fmt.Printf("│  gparent  : %s (pid %d)\n", lineage.gparentComm, lineage.gppid)
		}

		fmt.Println("└─────────────────────────────────────────────")
	}
}

func resolvPort(ev Event) (string, uint16) {
	port := ntohs(ev.ConPort)

	switch ev.ConFamily {
	case AF_INET:
		return net.IP(ev.Ipv4Addr[:]).String(), port
	case AF_INET6:
		return net.IP(ev.Ipv6Addr[:]).String(), port
	}

	return "unknown", port
}

func ntohs(n uint16) uint16 {
	return bits.ReverseBytes16(n)
}

func trimNull(inBytes []byte) string {
	return string(bytes.Trim(inBytes, "\x00"))
}
