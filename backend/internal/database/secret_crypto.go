package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

const secretKeyBytes = 32

func sealSecret(key []byte, raw string, prefix string) (string, error) {
	if len(key) != secretKeyBytes {
		return "", fmt.Errorf("加密密钥不可用")
	}
	block, err := aes.NewCipher(key)
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
	return prefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

func openSecret(key []byte, value string, prefix string, label string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, prefix) {
		return value, nil
	}
	if len(key) != secretKeyBytes {
		return "", fmt.Errorf("%s加密密钥不可用", label)
	}
	payload, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil {
		return "", fmt.Errorf("%s密文损坏: %w", label, err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(payload) < gcm.NonceSize() {
		return "", fmt.Errorf("%s密文长度不足", label)
	}
	nonce, ciphertext := payload[:gcm.NonceSize()], payload[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("%s解密失败: %w", label, err)
	}
	return string(plain), nil
}
