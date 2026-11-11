package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"sophon/internal/database"
)

func main() {
	dbPath := flag.String("db", "", "SQLite 数据库路径")
	projectID := flag.String("project", "", "项目 id")
	restoreFactID := flag.String("restore-fact", "", "恢复指定已归档事实 id")
	flag.Parse()
	if *dbPath == "" || *projectID == "" {
		fmt.Fprintln(os.Stderr, "usage: memory-cleanup -db /path/sophon.db -project <project-id>")
		os.Exit(2)
	}
	db, err := database.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()
	if *restoreFactID != "" {
		if err := db.RestoreProjectFact(context.Background(), *projectID, *restoreFactID); err != nil {
			fmt.Fprintf(os.Stderr, "restore project fact: %v\n", err)
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
			"restored": true,
			"factId":   *restoreFactID,
		})
		return
	}
	stats, err := db.CleanupProjectMemory(context.Background(), *projectID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cleanup project memory: %v\n", err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(stats)
}
