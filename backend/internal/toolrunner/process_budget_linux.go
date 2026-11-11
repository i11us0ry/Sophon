//go:build linux

package toolrunner

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const processBudgetPollInterval = 200 * time.Millisecond

func startProcessBudgetWatch(
	pgid int,
	cpuSeconds int,
	maxProcesses int,
) *processBudgetWatch {
	if pgid <= 0 || (cpuSeconds <= 0 && maxProcesses <= 0) {
		return nil
	}
	watch := newProcessBudgetWatch()
	go func() {
		defer close(watch.done)
		clockTicks := readClockTicks()
		ticker := time.NewTicker(processBudgetPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-watch.stop:
				return
			case <-ticker.C:
				processes, ticks, err := readProcessGroupUsage(pgid)
				if err != nil {
					continue
				}
				switch {
				case maxProcesses > 0 && processes > maxProcesses:
					watch.setReason(fmt.Sprintf("进程数 %d 超过上限 %d", processes, maxProcesses))
				case cpuSeconds > 0 && clockTicks > 0 &&
					ticks >= uint64(cpuSeconds)*uint64(clockTicks):
					watch.setReason(fmt.Sprintf("CPU 时间达到 %d 秒上限", cpuSeconds))
				default:
					continue
				}
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
				return
			}
		}
	}()
	return watch
}

func readProcessGroupUsage(pgid int) (int, uint64, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, 0, err
	}
	count := 0
	var ticks uint64
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			continue
		}
		state, processGroup, userTicks, systemTicks, err := parseProcStat(string(raw))
		if err != nil || processGroup != pgid {
			continue
		}
		if state == "Z" || state == "X" {
			continue
		}
		count++
		ticks += userTicks + systemTicks
	}
	return count, ticks, nil
}

func cleanupProcessGroup(pgid int) bool {
	processes, _, err := readProcessGroupUsage(pgid)
	if err != nil || processes == 0 {
		return false
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	return true
}

func processCPUSeconds(state *os.ProcessState) float64 {
	if state == nil {
		return 0
	}
	usage, ok := state.SysUsage().(*syscall.Rusage)
	if !ok || usage == nil {
		return 0
	}
	return timevalSeconds(usage.Utime) + timevalSeconds(usage.Stime)
}

func timevalSeconds(value syscall.Timeval) float64 {
	return float64(value.Sec) + float64(value.Usec)/1e6
}

func parseProcStat(raw string) (string, int, uint64, uint64, error) {
	end := strings.LastIndex(raw, ")")
	if end < 0 || end+2 >= len(raw) {
		return "", 0, 0, 0, fmt.Errorf("invalid proc stat")
	}
	fields := strings.Fields(raw[end+2:])
	if len(fields) < 13 {
		return "", 0, 0, 0, fmt.Errorf("short proc stat")
	}
	processGroup, err := strconv.Atoi(fields[2])
	if err != nil {
		return "", 0, 0, 0, err
	}
	userTicks, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return "", 0, 0, 0, err
	}
	systemTicks, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return "", 0, 0, 0, err
	}
	return fields[0], processGroup, userTicks, systemTicks, nil
}

func readClockTicks() int64 {
	raw, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return 100
	}
	for offset := 0; offset+16 <= len(raw); offset += 16 {
		kind := binary.LittleEndian.Uint64(raw[offset : offset+8])
		value := binary.LittleEndian.Uint64(raw[offset+8 : offset+16])
		if kind == 0 {
			break
		}
		if kind == 17 && value > 0 {
			return int64(value)
		}
	}
	return 100
}
