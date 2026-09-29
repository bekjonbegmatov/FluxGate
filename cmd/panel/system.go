package main

import (
	"bufio"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type cpuCounters struct{ total, idle, wait, softirq, steal uint64 }
type cpuUsageStats struct{ busy, wait, softirq, steal float64 }

var cpuSample struct {
	sync.Mutex
	previous cpuCounters
	usage    cpuUsageStats
}

// Reading/sorting 200k FD entries on every dashboard poll itself becomes work.
// Count in bounded pages and cache separately; it is diagnostic, not admission.
var descriptorSample struct {
	sync.Mutex
	count int
	at    time.Time
}

func processFDCount() (int, time.Time) {
	descriptorSample.Lock()
	defer descriptorSample.Unlock()
	if time.Since(descriptorSample.at) < 30*time.Second {
		return descriptorSample.count, descriptorSample.at
	}
	f, err := os.Open("/proc/self/fd")
	if err != nil {
		return 0, time.Time{}
	}
	defer f.Close()
	count := 0
	for {
		names, err := f.Readdirnames(1024)
		count += len(names)
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, time.Time{}
		}
	}
	descriptorSample.count, descriptorSample.at = count, time.Now()
	return count, descriptorSample.at
}

func parseCPUCounters(data []byte) (cpuCounters, bool) {
	fields := strings.Fields(strings.SplitN(string(data), "\n", 2)[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuCounters{}, false
	}
	var counts [8]uint64
	for i := 0; i < 8 && i+1 < len(fields); i++ {
		v, err := strconv.ParseUint(fields[i+1], 10, 64)
		if err != nil {
			return cpuCounters{}, false
		}
		counts[i] = v
	}
	// guest/guest_nice are already included in user/nice; do not sum twice.
	var total uint64
	for _, v := range counts {
		total += v
	}
	return cpuCounters{total, counts[3], counts[4], counts[6], counts[7]}, true
}
func cpuDelta(current, previous cpuCounters) cpuUsageStats {
	if current.total <= previous.total {
		return cpuUsageStats{}
	}
	delta := func(c, p uint64) float64 {
		if c < p {
			return 0
		}
		return float64(c-p) * 100 / float64(current.total-previous.total)
	}
	idle, wait, steal := delta(current.idle, previous.idle), delta(current.wait, previous.wait), delta(current.steal, previous.steal)
	return cpuUsageStats{max(0, min(100, 100-idle-wait-steal)), wait, delta(current.softirq, previous.softirq), steal}
}
func readCPUUsage() cpuUsageStats {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuUsageStats{}
	}
	current, ok := parseCPUCounters(data)
	if !ok {
		return cpuUsageStats{}
	}
	cpuSample.Lock()
	defer cpuSample.Unlock()
	if cpuSample.previous.total == 0 {
		cpuSample.previous = current
		return cpuUsageStats{}
	}
	if current.total == cpuSample.previous.total {
		return cpuSample.usage
	}
	cpuSample.usage = cpuDelta(current, cpuSample.previous)
	cpuSample.previous = current
	return cpuSample.usage
}

func readHostStats() map[string]any {
	out := map[string]any{"time": time.Now().Unix()}
	cpu := readCPUUsage()
	out["cpu_percent"], out["cpu_iowait_percent"], out["cpu_softirq_percent"], out["cpu_steal_percent"] = cpu.busy, cpu.wait, cpu.softirq, cpu.steal
	out["cpu_logical_cores"] = runtime.NumCPU()
	if b, e := os.ReadFile("/proc/loadavg"); e == nil {
		f := strings.Fields(string(b))
		if len(f) >= 3 {
			out["load1"], _ = strconv.ParseFloat(f[0], 64)
			out["load5"], _ = strconv.ParseFloat(f[1], 64)
			out["load15"], _ = strconv.ParseFloat(f[2], 64)
		}
	}
	if f, e := os.Open("/proc/meminfo"); e == nil {
		defer f.Close()
		m := map[string]uint64{}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			p := strings.Fields(strings.TrimSuffix(sc.Text(), ":"))
			if len(p) >= 2 {
				v, _ := strconv.ParseUint(p[1], 10, 64)
				m[strings.TrimSuffix(p[0], ":")] = v * 1024
			}
		}
		out["ram_total"] = m["MemTotal"]
		out["ram_used"] = m["MemTotal"] - m["MemAvailable"]
		out["swap_total"] = m["SwapTotal"]
		out["swap_used"] = m["SwapTotal"] - m["SwapFree"]
	}
	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) == nil {
		out["disk_total"] = st.Blocks * uint64(st.Bsize)
		out["disk_used"] = (st.Blocks - st.Bavail) * uint64(st.Bsize)
	}
	return out
}
func (a *App) systemAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		fail(w, 405, "method")
		return
	}
	stats := readHostStats()
	stats["process_started_at"] = a.start.UTC().Format(time.RFC3339Nano)
	stats["agent_pid"] = os.Getpid()
	stats["public_https_last_ok_unix"] = a.publicProbe.lastOK.Load()
	stats["public_https_failures"] = a.publicProbe.failures.Load()
	stats["public_https_last_ms"] = float64(a.publicProbe.lastNS.Load()) / 1e6
	stats["process_architecture"] = "supervisor/web/agent"
	a.mu.RLock()
	stats["direct_limits"] = a.directLimits
	a.mu.RUnlock()
	stats["quota_watchdog_ready"] = a.persistenceFresh(time.Now()) && a.directLastOK.Load() > 0 && time.Since(time.Unix(a.directLastOK.Load(), 0)) <= directLeaseTimeout
	direct := a.directMode()
	stats["proxy_mode"] = "relay"
	if direct {
		stats["proxy_mode"] = "direct"
	}
	stats["direct_stats_last_ok_unix"] = a.directLastOK.Load()
	stats["direct_stats_errors"] = a.directErrors.Load()
	stats["uptime_seconds"] = int64(time.Since(a.start).Seconds())
	stats["goroutines"] = runtime.NumGoroutine()
	heap := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(heap) // avoid ReadMemStats' global pause on every dashboard poll
	stats["heap_bytes"] = heap[0].Value.Uint64()
	active, paused, quota := 0, 0, 0
	quotasEnabled := a.quotasEnabled()
	var pending int64
	for _, s := range a.routeStates() {
		s.mu.Lock()
		active += len(s.conns)
		pending += s.pendingUp + s.pendingDown
		if s.Route.Paused {
			paused++
		}
		if quotasEnabled && s.blocked() {
			quota++
		}
		s.mu.Unlock()
	}
	stats["relay_connections"] = active
	stats["relay_admitted_connections"] = a.relayAdmitted.Load()
	stats["relay_capacity_rejections"] = a.relayRejected.Load()
	stats["relay_buffer_bytes"] = active * 2 * relayBufferSize
	stats["paused_routes"], stats["quota_routes"] = paused, quota
	stats["traffic_unsaved_bytes"] = pending
	stats["traffic_flush_last_ok_unix"] = a.flushLastOK.Load()
	stats["traffic_flush_last_ms"] = float64(a.flushLastNS.Load()) / 1e6
	stats["traffic_flush_errors"] = a.flushErrors.Load()
	stats["max_client_connections"] = a.maxConnections
	stats["public_connections"] = a.publicConnections.Load()
	stats["public_peak_connections"] = a.publicPeak.Load()
	if count, at := processFDCount(); !at.IsZero() {
		stats["agent_open_fds"], stats["agent_fds_sampled_at"] = count, at.Unix()
	}
	var limits syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limits) == nil {
		stats["agent_nofile_soft"], stats["agent_nofile_hard"] = limits.Cur, limits.Max
	}
	if raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range"); err == nil {
		stats["ephemeral_port_range"] = strings.TrimSpace(string(raw))
	}
	for _, name := range []string{"panel.db", "panel.db-wal", "panel.db-shm"} {
		if f, err := os.Stat(filepath.Join(a.data, name)); err == nil {
			stats[name+"_bytes"] = f.Size()
		}
	}
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && (f[0] == "VmRSS:" || f[0] == "VmSwap:") {
				n, _ := strconv.ParseInt(f[1], 10, 64)
				stats[strings.TrimSuffix(f[0], ":")+"_bytes"] = n * 1024
			}
		}
	}
	db := a.db.Stats()
	stats["db_wait_count"] = db.WaitCount
	stats["db_wait_seconds"] = db.WaitDuration.Seconds()
	writeJSON(w, 200, stats)
}
