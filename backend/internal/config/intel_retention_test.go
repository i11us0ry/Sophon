package config

import "testing"

func TestDefaultIntelSearchRetention(t *testing.T) {
	settings, ok := defaultStorageConfig().Categories["intel_searches"]
	if !ok || !settings.Enabled || settings.RetentionDays != 90 {
		t.Fatalf("信息收集历史默认保留期错误: %+v", settings)
	}
}
