package toolerror

import "testing"

func TestClassify(t *testing.T) {
	cases := map[string]Class{
		"status code: 429 too many requests": RateLimit,
		"context deadline exceeded":          Timeout,
		"proxy connect timeout":              Timeout,
		"proxy connection reset":             Network,
		"no such host":                       TargetUnreachable,
		"permission denied":                  Authorization,
		"invalid api key":                    Authentication,
		"Mission Policy 拒绝执行":                Policy,
		"禁止通过 nohup 启动进程":                    Policy,
		"命令退出码 2":                            CommandExit,
		"命令无匹配结果（退出码 1）":                     NoMatch,
		"parse arguments failed":             InvalidArguments,
		"unexpected failure":                 Tool,
	}
	for message, want := range cases {
		if got := Classify(message); got != want {
			t.Fatalf("分类 %q 期望 %s，实际 %s", message, want, got)
		}
	}
}

func TestRetryableAndBlocked(t *testing.T) {
	for _, class := range []Class{Timeout, RateLimit, Network} {
		if !Retryable(class) {
			t.Fatalf("%s 应可重试", class)
		}
	}
	for _, class := range []Class{Policy, Authorization, Authentication} {
		if !Blocked(class) || Retryable(class) {
			t.Fatalf("%s 应为不可重试阻断", class)
		}
	}
	for _, class := range []Class{CommandExit, NoMatch} {
		if Blocked(class) || Retryable(class) {
			t.Fatalf("%s 应为不可重试的普通命令结果", class)
		}
	}
}
