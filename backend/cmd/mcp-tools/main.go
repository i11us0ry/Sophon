package main

import (
	"context"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// 内置 MCP 服务保留为可扩展的空服务：平台自带工具由 sophon-tool-runner
// 从 tools/ 目录提供，这里不再注册任何演示工具。
func main() {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "sophon-tools",
		Version: "0.1.0",
	}, nil)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
