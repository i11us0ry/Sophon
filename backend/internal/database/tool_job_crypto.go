package database

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const (
	jobKeyBytes     = 32
	jobCipherPrefix = "enc:v1:"
)

func loadOrCreateJobKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		if len(raw) != jobKeyBytes {
			return nil, fmt.Errorf("Job 加密密钥长度无效")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("收紧 Job 加密密钥权限失败: %w", err)
		}
		return raw, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("读取 Job 加密密钥失败: %w", err)
	}
	key := make([]byte, jobKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("生成 Job 加密密钥失败: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			raw, readErr := os.ReadFile(path)
			if readErr != nil || len(raw) != jobKeyBytes {
				return nil, fmt.Errorf("读取并发创建的 Job 加密密钥失败")
			}
			return raw, nil
		}
		return nil, fmt.Errorf("创建 Job 加密密钥失败: %w", err)
	}
	if _, err := file.Write(key); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("写入 Job 加密密钥失败: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("关闭 Job 加密密钥失败: %w", err)
	}
	return key, nil
}

func (db *DB) encryptJobSteps(raw string) (string, error) {
	if db == nil || len(db.jobKey) != jobKeyBytes {
		return "", fmt.Errorf("Job 加密密钥不可用")
	}
	block, err := aes.NewCipher(db.jobKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(raw), nil)
	return jobCipherPrefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (db *DB) decryptJobSteps(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, jobCipherPrefix) {
		// 兼容升级前已经落库的明文 Job。
		return value, nil
	}
	if db == nil || len(db.jobKey) != jobKeyBytes {
		return "", fmt.Errorf("Job 加密密钥不可用")
	}
	payload, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, jobCipherPrefix))
	if err != nil {
		return "", fmt.Errorf("Job 步骤密文损坏: %w", err)
	}
	block, err := aes.NewCipher(db.jobKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(payload) < gcm.NonceSize() {
		return "", fmt.Errorf("Job 步骤密文长度不足")
	}
	nonce, ciphertext := payload[:gcm.NonceSize()], payload[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("Job 步骤解密失败: %w", err)
	}
	return string(plain), nil
}

func (db *DB) encryptLegacyToolJobSteps(ctx context.Context) error {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, steps_json FROM tool_jobs
		 WHERE substr(steps_json, 1, ?) <> ?`,
		len(jobCipherPrefix),
		jobCipherPrefix,
	)
	if err != nil {
		return err
	}
	items := map[string]string{}
	for rows.Next() {
		var id, steps string
		if err := rows.Scan(&id, &steps); err != nil {
			_ = rows.Close()
			return err
		}
		items[id] = steps
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	if len(items) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for id, steps := range items {
		encrypted, err := db.encryptJobSteps(steps)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE tool_jobs SET steps_json = ? WHERE id = ?`,
			encrypted,
			id,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}
