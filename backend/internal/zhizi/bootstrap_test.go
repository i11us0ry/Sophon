package zhizi

import (
	"os/exec"
	"strings"
	"testing"
)

func TestInitializationScriptContainsRuntimeAndMirrors(t *testing.T) {
	for _, expected := range []string{
		"repository_is_domestic",
		"backup_repository_file",
		"restore_repository_backups",
		"apt-get update",
		"dnf makecache",
		"yum makecache",
		"apk update",
		"need_command",
		"php_has_extension",
		"install_missing_packages",
		"mirrors.tuna.tsinghua.edu.cn",
		"mirrors.aliyun.com",
		"python3",
		"python3-venv",
		"php-cli",
		"php-mbstring",
		"default-jdk-headless",
		"pypi.tuna.tsinghua.edu.cn",
		"mirrors.aliyun.com/composer",
		"maven.aliyun.com/repository/public",
		"javac",
		"java -version",
	} {
		if !strings.Contains(InitializationScript, expected) {
			t.Fatalf("初始化脚本缺少 %q", expected)
		}
	}
}

func TestInitializationScriptHasValidBashSyntax(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash 不可用，跳过脚本语法检查")
	}
	command := exec.Command(bash, "-n")
	command.Stdin = strings.NewReader(InitializationScript)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("初始化脚本语法错误: %v\n%s", err, output)
	}
}
