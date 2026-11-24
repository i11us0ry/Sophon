package database

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntelSettingsEncryptsSecrets(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "intel-settings.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	if err := db.SaveIntelSettings(ctx, IntelSettings{
		Enabled:   true,
		FOFAEmail: "user@example.com",
		FOFAKey:   "fofa-secret-key",
		HunterKey: "hunter-secret-key",
	}); err != nil {
		t.Fatalf("保存信息设置失败: %v", err)
	}

	var fofaCipher, hunterCipher string
	if err := db.QueryRowContext(
		ctx,
		`SELECT fofa_key_cipher, hunter_key_cipher FROM intel_settings WHERE id = 'default'`,
	).Scan(&fofaCipher, &hunterCipher); err != nil {
		t.Fatalf("读取密钥密文失败: %v", err)
	}
	if strings.Contains(fofaCipher, "fofa-secret-key") ||
		strings.Contains(hunterCipher, "hunter-secret-key") {
		t.Fatalf("密钥不应明文落库: fofa=%q hunter=%q", fofaCipher, hunterCipher)
	}

	settings, err := db.GetIntelSettings(ctx)
	if err != nil {
		t.Fatalf("读取信息设置失败: %v", err)
	}
	if !settings.Enabled ||
		settings.FOFAEmail != "user@example.com" ||
		settings.FOFAKey != "fofa-secret-key" ||
		settings.HunterKey != "hunter-secret-key" {
		t.Fatalf("信息设置往返不一致: %+v", settings)
	}
}
