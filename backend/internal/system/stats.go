// Package system 采集主机与容器的运行时资源指标，不依赖第三方库。
package system

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Stats struct {
	Hostname         string    `json:"hostname"`
	OS               string    `json:"os"`
	Arch             string    `json:"arch"`
	CPUPercent       float64   `json:"cpuPercent"`
	CPUSupported     bool      `json:"cpuSupported"`
	MemoryPercent    float64   `json:"memoryPercent"`
	MemoryUsedBytes  uint64    `json:"memoryUsedBytes"`
	MemoryTotalBytes uint64    `json:"memoryTotalBytes"`
	MemorySource     string    `json:"memorySource"`
	CollectedAt      time.Time `json:"collectedAt"`
}

type Collector struct {
	mu           sync.Mutex
	cpuTotal     uint64
	cpuIdle      uint64
	cpuValue     float64
	cpuSupported bool
	cpuSampledAt time.Time
}

func NewCollector() *Collector {
	return &Collector{}
}

func (c *Collector) Collect() Stats {
	hostname, _ := os.Hostname()
	stats := Stats{
		Hostname:     strings.TrimSpace(hostname),
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		MemorySource: "unsupported",
		CollectedAt:  time.Now().UTC(),
	}

	if used, total, source, ok := readMemory(); ok {
		stats.MemoryUsedBytes = used
		stats.MemoryTotalBytes = total
		stats.MemoryPercent = percent(used, total)
		stats.MemorySource = source
	}
	stats.CPUPercent, stats.CPUSupported = c.cpuPercent()
	return stats
}

// cpuPercent 通过两次读取 /proc/stat 的差值计算 CPU 使用率；
// 首次调用只建立基线，返回 0。非 Linux 平台返回 unsupported。
func (c *Collector) cpuPercent() (float64, bool) {
	total, idle, err := readCPUStat()
	if err != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.cpuValue, c.cpuSupported
	}

	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cpuSupported && !c.cpuSampledAt.IsZero() && now.Sub(c.cpuSampledAt) >= 200*time.Millisecond {
		deltaTotal := total - c.cpuTotal
		deltaIdle := idle - c.cpuIdle
		if deltaTotal > 0 && deltaIdle <= deltaTotal {
			c.cpuValue = percent(deltaTotal-deltaIdle, deltaTotal)
		}
	}
	c.cpuTotal = total
	c.cpuIdle = idle
	c.cpuSampledAt = now
	c.cpuSupported = true
	return c.cpuValue, true
}

func readCPUStat() (uint64, uint64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:]
		if len(fields) < 4 {
			return 0, 0, errUnsupported
		}
		var total uint64
		for _, field := range fields {
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				return 0, 0, err
			}
			total += value
		}
		idle, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			return 0, 0, err
		}
		if len(fields) > 4 {
			if iowait, err := strconv.ParseUint(fields[4], 10, 64); err == nil {
				idle += iowait
			}
		}
		return total, idle, nil
	}
	return 0, 0, errUnsupported
}

// readMemory 优先使用 cgroup 限制（容器视角），否则回退 /proc/meminfo。
func readMemory() (uint64, uint64, string, bool) {
	if current, err := readUintFile("/sys/fs/cgroup/memory.current"); err == nil {
		if limit, err := readUintFile("/sys/fs/cgroup/memory.max"); err == nil && limit > 0 {
			return current, limit, "cgroup", true
		}
	}
	if current, err := readUintFile("/sys/fs/cgroup/memory/memory.usage_in_bytes"); err == nil {
		if limit, err := readUintFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil &&
			limit > 0 && limit < 1<<60 {
			return current, limit, "cgroup", true
		}
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, "unsupported", false
	}
	var totalKB uint64
	var availableKB uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			totalKB = value
		case "MemAvailable:":
			availableKB = value
		}
	}
	if totalKB == 0 {
		return 0, 0, "unsupported", false
	}
	if availableKB > totalKB {
		availableKB = totalKB
	}
	return (totalKB - availableKB) * 1024, totalKB * 1024, "host", true
}

func readUintFile(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

func percent(part, total uint64) float64 {
	if total == 0 {
		return 0
	}
	value := float64(part) / float64(total) * 100
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	rounded := float64(int(value*10+0.5)) / 10
	return rounded
}

type unsupportedError struct{}

func (unsupportedError) Error() string {
	return "当前平台不支持该指标"
}

var errUnsupported = unsupportedError{}
