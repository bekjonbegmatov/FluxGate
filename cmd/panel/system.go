package main

import (
	"bufio"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var cpuSample struct {
	sync.Mutex
	total, idle uint64
}

func cpuPercent() float64 {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	f := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
	if len(f) < 5 {
		return 0
	}
	var total, idle uint64
	for i := 1; i < len(f); i++ {
		v, _ := strconv.ParseUint(f[i], 10, 64)
		total += v
		if i == 4 || i == 5 {
			idle += v
		}
	}
	cpuSample.Lock()
	defer cpuSample.Unlock()
	if cpuSample.total == 0 {
		cpuSample.total, cpuSample.idle = total, idle
		return 0
	}
	dt, di := total-cpuSample.total, idle-cpuSample.idle
	cpuSample.total, cpuSample.idle = total, idle
	if dt == 0 {
		return 0
	}
	return float64(dt-di) * 100 / float64(dt)
}

func readHostStats() map[string]any {
	out := map[string]any{"time": time.Now().Unix()}
	out["cpu_percent"] = cpuPercent()
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
	writeJSON(w, 200, readHostStats())
}
