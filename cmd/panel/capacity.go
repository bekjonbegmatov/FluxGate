package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
)

const defaultMaxConnections = 10000
const maximumConnections = 100000

func parseMaxConnections(value string) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 || n > maximumConnections {
		return 0, fmt.Errorf("PANEL_MAX_CONNECTIONS must be between 1 and %d", maximumConnections)
	}
	return n, nil
}

func (a *App) connectionLimit() int {
	if a.maxConnections == 0 {
		return defaultMaxConnections
	}
	return a.maxConnections
}

// The outer local hop has no ephemeral TCP port pool.
func relaySocket(data string, id int64) string {
	return filepath.Join(data, fmt.Sprintf("relay-%d.sock", id))
}

const internalTLSFirstPort = 8443
const internalTLSShards = 16

// Keep TCP on the inner hop: an abortive close (RST) releases HAProxy's TLS/WS
// stream. Unix EOF alone can leave upgraded streams alive for the tunnel timeout.
// Distinct destination ports provide distinct TCP tuple pools. Least-active
// allocation prevents uneven session lifetimes from concentrating on one pool;
// rotating ties spreads short-lived traffic too. Never hold mu during dialing.
type internalTLSIngress struct {
	mu     sync.Mutex
	active [internalTLSShards]int
	next   int
}

func (p *internalTLSIngress) acquire() (string, func()) {
	p.mu.Lock()
	selected := p.next
	for n := 1; n < internalTLSShards; n++ {
		i := (p.next + n) % internalTLSShards
		if p.active[i] < p.active[selected] {
			selected = i
		}
	}
	p.active[selected]++
	p.next = (selected + 1) % internalTLSShards
	p.mu.Unlock()
	return fmt.Sprintf("127.0.0.1:%d", internalTLSFirstPort+selected), func() {
		p.mu.Lock()
		p.active[selected]--
		p.mu.Unlock()
	}
}

func internalTLSBind() string {
	return fmt.Sprintf("127.0.0.1:%d-%d", internalTLSFirstPort, internalTLSFirstPort+internalTLSShards-1)
}

// Shared by all routes and HAProxy generations; reserve before spawning a pump
// or dialing the inner hop. Reload cannot allocate unbounded Go buffers/FDs.
func (a *App) acquireRelay() bool {
	for {
		n := a.relayAdmitted.Load()
		if n >= int64(a.connectionLimit()) {
			a.relayRejected.Add(1)
			return false
		}
		if a.relayAdmitted.CompareAndSwap(n, n+1) {
			return true
		}
	}
}
