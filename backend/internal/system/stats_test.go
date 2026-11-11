package system

import (
	"strings"
	"testing"
	"time"
)

func TestCollectReturnsHostIdentity(t *testing.T) {
	collector := NewCollector()
	stats := collector.Collect()
	if strings.TrimSpace(stats.Hostname) == "" {
		t.Fatal("hostname should not be empty")
	}
	if stats.OS == "" || stats.Arch == "" {
		t.Fatalf("os/arch missing: %+v", stats)
	}
	if stats.MemoryPercent < 0 || stats.MemoryPercent > 100 {
		t.Fatalf("memory percent out of range: %v", stats.MemoryPercent)
	}
	if stats.CPUPercent < 0 || stats.CPUPercent > 100 {
		t.Fatalf("cpu percent out of range: %v", stats.CPUPercent)
	}
}

func TestCollectorKeepsPreviousCPUValueWithoutSampleGap(t *testing.T) {
	collector := NewCollector()
	first := collector.Collect()
	time.Sleep(10 * time.Millisecond)
	second := collector.Collect()
	if first.CPUSupported != second.CPUSupported {
		t.Fatalf("cpu support flag changed between samples: %v -> %v", first.CPUSupported, second.CPUSupported)
	}
}

func TestReadMemoryDegradesGracefully(t *testing.T) {
	used, total, source, ok := readMemory()
	if !ok {
		if source != "unsupported" {
			t.Fatalf("unsupported platform should report source=unsupported, got %q", source)
		}
		return
	}
	if source != "cgroup" && source != "host" {
		t.Fatalf("unexpected memory source: %q", source)
	}
	if total == 0 || used > total {
		t.Fatalf("invalid memory values: used=%d total=%d", used, total)
	}
}
