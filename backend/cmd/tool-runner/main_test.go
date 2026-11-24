package main

import (
	"errors"
	"strings"
	"testing"

	"sophon/internal/toolrunner"
)

func TestRenderResultTruncatesLongCommand(t *testing.T) {
	longCommand := "python3 -c " + strings.Repeat("x", 20000)
	output := renderResult(&toolrunner.Result{
		Command: longCommand,
		Output:  "Request failed: [Errno -2] Name or service not known\n",
	}, nil, false)
	if !strings.Contains(output, "命令回显已省略") {
		t.Fatalf("超长命令应被截断并标注: %q", output[:200])
	}
	if strings.Contains(output, strings.Repeat("x", 2000)) {
		t.Fatalf("命令回显仍然过长")
	}
	if !strings.Contains(output, "Name or service not known") {
		t.Fatalf("输出内容应完整保留: %q", output)
	}
}

func TestRenderResultKeepsErrorAndOutput(t *testing.T) {
	output := renderResult(&toolrunner.Result{
		Command: "sqlmap -u http://example.com",
		Output:  "boom",
	}, errors.New("命令退出码 1"), false)
	for _, want := range []string{"$ sqlmap -u http://example.com", "错误: 命令退出码 1", "boom"} {
		if !strings.Contains(output, want) {
			t.Fatalf("输出缺少 %q: %q", want, output)
		}
	}
}

func TestRenderResultDescribesNoMatchAsStatus(t *testing.T) {
	output := renderResult(&toolrunner.Result{
		Command:  "grep -R missing src",
		ExitCode: 1,
	}, errors.New("命令退出码 1"), true)
	if strings.Contains(output, "错误:") || !strings.Contains(output, "命令无匹配结果") {
		t.Fatalf("无匹配结果不应显示为工具错误: %q", output)
	}
}

func TestNoMatchResultRecognition(t *testing.T) {
	args := map[string]any{"command": "grep -R missing src"}
	result := &toolrunner.Result{ExitCode: 1}
	if !isNoMatchResult("exec", args, result, errors.New("命令退出码 1")) {
		t.Fatal("grep 退出码 1 应识别为无匹配")
	}
	result.Output = "grep: src: No such file or directory"
	if isNoMatchResult("exec", args, result, errors.New("命令退出码 1")) {
		t.Fatal("路径错误不应识别为无匹配")
	}
}

func TestCommandResultPayloadCarriesExitMetadata(t *testing.T) {
	result := &toolrunner.Result{
		Command:   "grep -R missing src",
		ExitCode:  2,
		Truncated: true,
	}
	payload := commandResultPayload(
		"exec",
		map[string]any{"command": "grep -R missing src"},
		result,
		errors.New("命令退出码 2"),
		false,
	)
	if payload.ExitCode == nil ||
		*payload.ExitCode != 2 ||
		!payload.Truncated ||
		payload.ErrorClass != "command_exit" ||
		payload.Status != "error" {
		t.Fatalf("结构化命令结果异常: %+v", payload)
	}
}

func TestRenderResultAddsMissingRuntimeCommandHints(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		output string
		want   []string
	}{
		{
			name:   "file",
			output: "sh: 1: file: not found\n",
			want:   []string{"环境提示：file 不可用", "stat", "od"},
		},
		{
			name:   "time",
			output: "sh: 20: time: not found\n",
			want:   []string{"环境提示：外部 time 不可用", "perf_counter", "date +%s%N"},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			output := renderResult(&toolrunner.Result{
				Command: "sh -c " + testCase.name,
				Output:  testCase.output,
			}, errors.New("命令退出码 127"), false)
			for _, want := range append([]string{
				"错误: 命令退出码 127",
				testCase.output,
			}, testCase.want...) {
				if !strings.Contains(output, want) {
					t.Fatalf("输出缺少 %q: %q", want, output)
				}
			}
		})
	}
}

func TestRenderResultIgnoresUnrelatedNotFoundMessage(t *testing.T) {
	output := renderResult(&toolrunner.Result{
		Output: "profile: not found while reading config\n",
	}, errors.New("命令退出码 1"), false)
	if strings.Contains(output, "环境提示") {
		t.Fatalf("无关的 not found 文本不应触发命令替代提示: %q", output)
	}
}

func TestRenderResultIncludesCPUUsage(t *testing.T) {
	output := renderResult(&toolrunner.Result{
		Output:      "ok\n",
		CPUSeconds:  1.25,
		BudgetToken: "job-token",
	}, nil, false)
	if !strings.Contains(output, "[sophon budget:job-token] cpu_seconds=1.250000") {
		t.Fatalf("输出缺少 CPU 使用量: %q", output)
	}
}
