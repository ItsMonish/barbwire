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

	go c.cleanUp()
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

func (c *Correlator) cleanUp() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()

		for pid, opens := range c.recentOpens {
			var freshEntries []OpenEntry
			for _, open := range opens {
				if now.Sub(open.timestamp) <= c.window {
					freshEntries = append(freshEntries, open)
				}
			}
			if len(freshEntries) != 0 {
				c.recentOpens[pid] = freshEntries
			} else {
				delete(c.recentOpens, pid)
			}
		}

		c.mu.Unlock()
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
