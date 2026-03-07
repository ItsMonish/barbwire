package correlator

import (
	"bytes"
	"fmt"
	"math/bits"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ItsMonish/barbwire/internal/config"
	"github.com/ItsMonish/barbwire/internal/scoring"
	"github.com/ItsMonish/barbwire/internal/types"
)

type Correlator struct {
	mu          sync.Mutex
	recentOpens map[int32][]types.OpenEntry
	lineage     map[int32]types.LineageEntry
	window      time.Duration
	scorer      *scoring.Scorer
	threshold   int
	seen        map[types.SeenKey]time.Time
	whitelist   config.IgnoredDestinations
}

func NewCorrelator(conf *config.Config) *Correlator {
	s := scoring.NewScorer(conf)
	c := &Correlator{
		recentOpens: make(map[int32][]types.OpenEntry),
		lineage:     make(map[int32]types.LineageEntry),
		window:      time.Duration(conf.CorrelationWindowSeconds) * time.Second,
		scorer:      s,
		threshold:   conf.AlertThreshold,
		seen:        make(map[types.SeenKey]time.Time),
		whitelist:   conf.IgnoredDestinations,
	}

	go c.cleanUp()
	return c
}

func (c *Correlator) HandleEvent(ev types.Event) {
	switch ev.Type {
	case types.EventOpen:
		c.handleOpen(ev)
	case types.EventConnect:
		c.handleConnect(ev)
	case types.EventExec:
		c.handleExec(ev)
	}
}

func (c *Correlator) handleOpen(ev types.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry := types.OpenEntry{
		Timestamp: time.Now(),
		Fname:     trimNull(ev.Fname[:]),
	}

	c.recentOpens[ev.Pid] = append(c.recentOpens[ev.Pid], entry)
}

func (c *Correlator) handleExec(ev types.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lineage[ev.Pid] = types.LineageEntry{
		Ppid:        ev.Ppid,
		Gppid:       ev.Gppid,
		ParentComm:  trimNull(ev.ParentCommand[:]),
		GparentComm: trimNull(ev.GParentCommand[:]),
	}
}

func (c *Correlator) handleConnect(ev types.Event) {
	if ev.ConFamily != types.AF_INET && ev.ConFamily != types.AF_INET6 {
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
	var bestOpen *types.OpenEntry
	var bestResult scoring.SeverityResult
	for i, open := range opens {
		if now.Sub(open.Timestamp) > c.window {
			continue
		}

		var lin *types.LineageEntry
		if hasLineage {
			lin = &lineage
		}

		result := c.scorer.ScoreEvent(open.Fname, lin)
		if result.Score > bestResult.Score {
			bestResult = result
			bestOpen = &opens[i]
		}
	}

	if bestOpen == nil || bestResult.Score < c.threshold {
		return
	}

	command := trimNull(ev.Command[:])
	addr, port := resolvPort(ev)

	for _, p := range c.whitelist.Ports {
		if port == uint16(p) {
			return
		}
	}
	if slices.Contains(c.whitelist.IPs, addr) {
		return
	}

	key := types.SeenKey{Pid: ev.Pid, Addr: addr, Port: port}

	c.mu.Lock()
	if last, ok := c.seen[key]; ok && now.Sub(last) < c.window {
		c.mu.Unlock()
		return
	}
	c.seen[key] = now
	c.mu.Unlock()

	fmt.Printf("\n┌─ barbwire alert — PID %-6d ─────────────\n", ev.Pid)
	fmt.Printf("│  command  : %s\n", command)
	fmt.Printf("│  file     : %s\n", bestOpen.Fname)
	fmt.Printf("│  connect  : %s:%d\n", addr, port)
	fmt.Printf("│  severity : %s\n", bestResult.Severity)
	fmt.Printf("│  reasons  : %s\n", strings.Join(bestResult.Reasons, ", "))
	if hasLineage {
		fmt.Printf("│  parent   : %s (pid %d)\n", lineage.ParentComm, lineage.Ppid)
		fmt.Printf("│  gparent  : %s (pid %d)\n", lineage.GparentComm, lineage.Gppid)
	}
	fmt.Println("└─────────────────────────────────────────────")
}

func (c *Correlator) cleanUp() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()

		for pid, opens := range c.recentOpens {
			var freshEntries []types.OpenEntry
			for _, open := range opens {
				if now.Sub(open.Timestamp) <= c.window {
					freshEntries = append(freshEntries, open)
				}
			}
			if len(freshEntries) != 0 {
				c.recentOpens[pid] = freshEntries
			} else {
				delete(c.recentOpens, pid)
			}

			for key, t := range c.seen {
				if now.Sub(t) > c.window {
					delete(c.seen, key)
				}
			}
		}

		c.mu.Unlock()
	}
}

func resolvPort(ev types.Event) (string, uint16) {
	port := ntohs(ev.ConPort)

	switch ev.ConFamily {
	case types.AF_INET:
		return net.IP(ev.Ipv4Addr[:]).String(), port
	case types.AF_INET6:
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
