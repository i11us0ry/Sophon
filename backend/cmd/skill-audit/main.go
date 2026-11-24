package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"sophon/internal/skillaudit"
)

func main() {
	var dir string
	var jsonOutput bool
	var strict bool
	flag.StringVar(&dir, "dir", "skills", "Skill 根目录")
	flag.BoolVar(&jsonOutput, "json", false, "输出 JSON")
	flag.BoolVar(&strict, "strict", false, "存在不合规 Skill 时返回非零退出码")
	flag.Parse()

	report, err := skillaudit.AuditDir(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if jsonOutput {
		raw, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(string(raw))
	} else {
		fmt.Printf(
			"root=%s total=%d compliant=%d nonCompliant=%d\n",
			report.Root,
			report.Total,
			report.Compliant,
			report.NonCompliant,
		)
		for _, result := range report.Results {
			if result.Compliant {
				continue
			}
			for _, issue := range result.Issues {
				fmt.Printf(
					"[%s] %s %s: %s\n",
					issue.Severity,
					result.Name,
					issue.Code,
					issue.Message,
				)
			}
		}
	}
	if strict && report.NonCompliant > 0 {
		os.Exit(2)
	}
}
