//go:build !linux

package toolrunner

import "os"

func startProcessBudgetWatch(
	pgid int,
	cpuSeconds int,
	maxProcesses int,
) *processBudgetWatch {
	return nil
}

func cleanupProcessGroup(pgid int) bool {
	return false
}

func processCPUSeconds(state *os.ProcessState) float64 {
	return 0
}
