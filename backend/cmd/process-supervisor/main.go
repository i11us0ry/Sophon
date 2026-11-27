package main

import (
	"os"

	"sophon/internal/procwrap"
)

func main() {
	os.Exit(procwrap.RunSupervisor(os.Args[1:]))
}
