package handler

import "sync"

// configMutationMu 串行化基本设置与存储设置的读-合并-写-热更新事务。
var configMutationMu sync.Mutex
