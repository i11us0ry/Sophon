package policy

import "testing"

func TestContainsDetachedBackground(t *testing.T) {
	for _, command := range []string{
		"sleep 10 &",
		"nohup ./scan.sh >scan.log 2>&1",
		"setsid ./scan.sh",
		"disown",
		"coproc scan",
		"(sleep 10 &)",
		"sh -c 'sleep 10 &'",
		"bash -c \"nohup ./scan.sh >scan.log 2>&1\"",
	} {
		if !ContainsDetachedBackground(command) {
			t.Fatalf("应识别后台启动命令: %q", command)
		}
	}
	for _, command := range []string{
		"./scan.sh 2>&1",
		"grep foo file && echo ok",
		"./scan.sh &>scan.log",
		"grep nohup source.txt",
		"python3 - <<'PY'\nvalue = 1 & 2\nprint(value)\nPY",
	} {
		if ContainsDetachedBackground(command) {
			t.Fatalf("不应误判普通命令: %q", command)
		}
	}
}

func TestContainsDetachedLauncher(t *testing.T) {
	for _, script := range []string{
		"import os\nos.setsid()",
		"subprocess.Popen(cmd, start_new_session=True)",
	} {
		if !ContainsDetachedLauncher(script) {
			t.Fatalf("应识别解释器脱离会话调用: %q", script)
		}
	}
	if ContainsDetachedLauncher("print('normal')") {
		t.Fatalf("普通 Python 脚本不应被拒绝")
	}
}
