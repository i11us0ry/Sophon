package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sophon/internal/database"

	"github.com/gin-gonic/gin"
)

func (h *ChatHandler) StreamAgentEvents(c *gin.Context) {
	conversation, ok := h.conversationForRequest(c)
	if !ok {
		return
	}
	after, err := strconv.ParseInt(strings.TrimSpace(c.DefaultQuery("after", "0")), 10, 64)
	if err != nil || after < 0 {
		badRequest(c, "invalid_after", "after 参数不合法")
		return
	}
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		internalError(c, "stream_unsupported", "当前服务器不支持流式响应")
		return
	}
	c.Header("Content-Type", "text/event-stream; charset=utf-8")
	c.Header("Cache-Control", "no-cache, no-transform")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)

	if sessions, err := h.db.ListAgentSessions(c.Request.Context(), conversation.ID); err == nil {
		writeAgentEvent(c.Writer, "snapshot", gin.H{
			"conversationId": conversation.ID,
			"cursor":         after,
			"sessions":       sessions,
		})
		flusher.Flush()
	}

	poll := time.NewTicker(500 * time.Millisecond)
	heartbeat := time.NewTicker(10 * time.Second)
	defer poll.Stop()
	defer heartbeat.Stop()
	cursor := after
	for {
		select {
		case <-c.Request.Context().Done():
			return
		case <-heartbeat.C:
			if !writeAgentEvent(c.Writer, "heartbeat", gin.H{
				"cursor": cursor,
			}) {
				return
			}
			flusher.Flush()
		case <-poll.C:
			items, next, err := h.db.ListAgentSessionDetailsAfter(
				c.Request.Context(),
				conversation.ID,
				cursor,
				200,
			)
			if err != nil {
				return
			}
			if len(items) == 0 {
				continue
			}
			cursor = next
			sessions, _ := h.db.ListAgentSessions(c.Request.Context(), conversation.ID)
			if !writeAgentEvent(c.Writer, "agent_batch", gin.H{
				"conversationId": conversation.ID,
				"cursor":         cursor,
				"items":          agentEventDetails(items),
				"sessions":       sessions,
			}) {
				return
			}
			flusher.Flush()
		}
	}
}

func writeAgentEvent(writer gin.ResponseWriter, event string, payload interface{}) bool {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	if _, err := fmt.Fprintf(writer, "event: %s\ndata: %s\n\n", event, encoded); err != nil {
		return false
	}
	return true
}

func agentEventDetails(items []database.ProcessDetail) []gin.H {
	result := make([]gin.H, 0, len(items))
	for _, item := range items {
		result = append(result, gin.H{
			"id":        item.ID,
			"sequence":  item.Sequence,
			"eventType": item.EventType,
			"message":   item.Message,
			"data":      item.Data,
			"messageId": item.MessageID,
			"sessionId": item.SessionID,
			"createdAt": item.CreatedAt,
		})
	}
	return result
}
