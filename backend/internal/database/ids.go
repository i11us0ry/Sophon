package database

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

func newID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("id_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}
