package agent

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sophon/internal/database"
)

const (
	// 触发压缩：上下文估算 token 达到预算的 80%；压缩后目标保留 60%。
	compactionTriggerPct = 80
	compactionKeepPct    = 60
	// minor 增量压缩更频繁；major 全量重写用于消除摘要漂移，冷却更久。
	compactionMinorCooldown = 60 * time.Second
	compactionMajorCooldown = 10 * time.Minute
	compactionMajorEveryN   = 5
	compactionTimeout       = 5 * time.Minute
	compactionKindMinor     = "minor"
	compactionKindMajor     = "major"
	// 向量回填独立超时，避免占满压缩时间窗。
	memoryEmbeddingBackfillTimeout = 60 * time.Second
	// major 重写时回读的历史原文长度与 transcript 文件数。
	transcriptReseedRunes = 6000
	transcriptReseedFiles = 3
	// 超长消息截断标记：提示模型原文已外置到 transcript。
	contextTruncateMarker = "\n\n[...上下文已截断，完整原文见会话 transcript...]\n\n"
	transcriptDirName     = "summarization"
	transcriptMaxMessages = 500
)

// groupMessageRounds 把历史切成「回合」：user 消息开启新回合，
// 其后的 assistant 消息归入同一回合；回合是压缩与裁剪的最小单位，避免拆散问答对。
func groupMessageRounds(messages []database.Message) [][]database.Message {
	rounds := make([][]database.Message, 0, len(messages))
	for _, message := range messages {
		role := strings.ToLower(strings.TrimSpace(message.Role))
		if role == "user" || len(rounds) == 0 {
			rounds = append(rounds, []database.Message{message})
			continue
		}
		last := len(rounds) - 1
		rounds[last] = append(rounds[last], message)
	}
	return rounds
}

func estimateDatabaseMessagesTokens(messages []database.Message) int {
	total := 0
	for _, message := range messages {
		total += estimateTextTokensV2(message.Content) + 4
		total += estimateTextTokensV2(message.ReasoningContent)
	}
	return total
}

// truncateMessageContent 头尾保留 + 中间省略，避免只截尾部丢掉结论。
func truncateMessageContent(content string, maxTokens int) string {
	runes := []rune(strings.TrimSpace(content))
	if maxTokens <= 0 || len(runes) <= maxTokens {
		return string(runes)
	}
	head := maxTokens * 3 / 5
	tail := maxTokens - head
	if head <= 0 || tail <= 0 {
		return string(runes[:maxTokens]) + "…"
	}
	return string(runes[:head]) + contextTruncateMarker + string(runes[len(runes)-tail:])
}

// softBudgetMessages 是模型调用前的兜底：按回合从旧到新丢弃，仍超预算时截断最新回合的长消息。
// 该函数永不失败，保证请求不会因为上下文超限被上游拒绝。
func softBudgetMessages(messages []database.Message, budgetTokens int) []database.Message {
	if budgetTokens <= 0 || len(messages) == 0 {
		return messages
	}
	if estimateDatabaseMessagesTokens(messages) <= budgetTokens {
		return messages
	}

	rounds := groupMessageRounds(messages)
	kept := make([][]database.Message, 0, len(rounds))
	used := 0
	for index := len(rounds) - 1; index >= 0; index-- {
		size := estimateDatabaseMessagesTokens(rounds[index])
		if used+size > budgetTokens && len(kept) > 0 {
			break
		}
		kept = append(kept, rounds[index])
		used += size
	}
	if len(kept) == 0 {
		kept = append(kept, rounds[len(rounds)-1])
	}

	// 还原时间顺序。
	result := make([]database.Message, 0, len(messages))
	for index := len(kept) - 1; index >= 0; index-- {
		result = append(result, kept[index]...)
	}
	if estimateDatabaseMessagesTokens(result) <= budgetTokens {
		return result
	}

	// 最新回合仍然超预算：按 token 估算截断每条消息。
	perMessage := budgetTokens / maxInt(1, len(result))
	if perMessage < 64 {
		perMessage = 64
	}
	for index := range result {
		current := estimateTextTokensV2(result[index].Content) + 4
		if current <= perMessage {
			continue
		}
		result[index].Content = truncateMessageContent(result[index].Content, perMessage)
	}
	return result
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

// transcriptDir 返回会话压缩原文目录：<artifact_root>/data/conversation_artifacts/<conv>/summarization。
func (s *Service) transcriptDir(conversationID string) string {
	snapshot := s.configSnapshot()
	root := strings.TrimSpace(snapshot.Storage.ArtifactRoot)
	conversationID = strings.TrimSpace(conversationID)
	if root == "" || conversationID == "" {
		return ""
	}
	return filepath.Join(root, "data", "conversation_artifacts", conversationID, transcriptDirName)
}

// writeTranscript 在压缩前落盘原文，摘要里只保留路径引用，需要时可回读。
func (s *Service) writeTranscript(conversationID string, messages []database.Message) (string, error) {
	dir := s.transcriptDir(conversationID)
	if dir == "" || len(messages) == 0 {
		return "", nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("创建 transcript 目录失败: %w", err)
	}
	var builder strings.Builder
	for _, message := range messages {
		builder.WriteString("[" + message.CreatedAt.UTC().Format(time.RFC3339) + "] ")
		builder.WriteString(strings.TrimSpace(message.Role))
		builder.WriteString(":\n")
		builder.WriteString(message.Content)
		builder.WriteString("\n\n---\n\n")
	}
	name := fmt.Sprintf("transcript-%d.txt", time.Now().UTC().UnixNano())
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(builder.String()), 0o600); err != nil {
		return "", fmt.Errorf("写入 transcript 失败: %w", err)
	}
	return path, nil
}

// compactConversation 执行一次结构化压缩：原文落盘 → 模型摘要 → 写回摘要与审计记录。
func (s *Service) compactConversation(
	ctx context.Context,
	conversationID string,
	userID string,
	kind string,
) error {
	if s.db == nil || strings.TrimSpace(conversationID) == "" {
		return nil
	}
	kind = normalizeCompactionKind(kind)
	history, err := s.db.GetMessages(ctx, conversationID, transcriptMaxMessages)
	if err != nil {
		return err
	}
	stored, err := s.db.GetConversationSummary(ctx, conversationID)
	if err != nil {
		return err
	}
	previous := ""
	version := 0
	candidates := history
	if stored != nil {
		previous = stored.Summary
		version = stored.Version
		for index, message := range history {
			if message.ID == stored.ThroughMessageID {
				candidates = history[index+1:]
				break
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	budget := s.contextBudgetTokens()
	totalTokens := estimateDatabaseMessagesTokens(candidates)
	if totalTokens*100 < budget*compactionTriggerPct {
		return nil
	}

	keepBudget := budget * compactionKeepPct / 100
	split := len(candidates)
	used := 0
	for index := len(candidates) - 1; index >= 0; index-- {
		size := estimateTextTokensV2(candidates[index].Content) + 4
		if used+size > keepBudget && split < len(candidates) {
			break
		}
		used += size
		split = index
	}
	if split <= 0 {
		return nil
	}
	older := candidates[:split]
	recent := candidates[split:]

	transcriptPath, transcriptErr := s.writeTranscript(conversationID, older)
	if transcriptErr != nil {
		log.Printf("agent: 压缩原文落盘失败 conversation=%s: %v", conversationID, transcriptErr)
	}

	var result summaryCallResult
	if kind == compactionKindMajor {
		// major：回读最近几份 transcript 原文重新生成摘要，消除"摘要的摘要"漂移。
		reseed := s.readRecentTranscripts(conversationID, transcriptReseedFiles)
		if strings.TrimSpace(reseed) != "" {
			folded := reseed + "\n\n【新增历史】\n" + mergeSummary("", older, summaryInputRunes)
			result = s.summarizeText(ctx, folded, summaryOutputRunesMajor, transcriptPath)
		} else {
			result = s.summarizeOlderMessages(ctx, previous, older, transcriptPath)
		}
	} else {
		result = s.summarizeOlderMessages(ctx, previous, older, transcriptPath)
	}
	if strings.TrimSpace(result.Text) == "" {
		return fmt.Errorf("摘要结果为空")
	}
	if patterns := scanInjectionPatterns(result.Text); len(patterns) > 0 {
		s.recordSummaryInjection(ctx, conversationID, patterns)
	}
	through := older[len(older)-1].ID
	if err := s.db.SaveConversationSummary(ctx, database.ConversationSummary{
		ConversationID:   conversationID,
		Summary:          result.Text,
		ThroughMessageID: through,
		Version:          version + 1,
		TokenBefore:      totalTokens,
		TokenAfter:       estimateDatabaseMessagesTokens(recent) + estimateTextTokensV2(result.Text),
		TranscriptPath:   transcriptPath,
		UpdatedAt:        time.Now().UTC(),
	}); err != nil {
		return err
	}
	compactionID := randomID()
	if err := s.db.AddContextCompaction(ctx, database.ContextCompaction{
		ID:             compactionID,
		ConversationID: conversationID,
		TokensBefore:   totalTokens,
		TokensAfter:    estimateDatabaseMessagesTokens(recent) + estimateTextTokensV2(result.Text),
		SummaryTokens:  estimateTextTokensV2(result.Text),
		Kind:           kind,
		Model:          result.Model,
		LatencyMs:      result.LatencyMs,
		TriggerRatio:   float64(compactionTriggerPct) / 100,
		TranscriptPath: transcriptPath,
		CreatedAt:      time.Now().UTC(),
	}); err != nil {
		log.Printf("agent: 记录压缩审计失败 conversation=%s: %v", conversationID, err)
	}
	if result.TotalTokens > 0 {
		_ = s.db.AddTokenUsage(ctx, database.TokenUsage{
			ID:               randomID(),
			ConversationID:   conversationID,
			UserID:           userID,
			PromptTokens:     result.PromptTokens,
			CacheReadTokens:  result.CacheReadTokens,
			CompletionTokens: result.CompletionTokens,
			TotalTokens:      result.TotalTokens,
			Estimated:        result.Estimated,
			Kind:             "summary",
			Model:            result.Model,
			CreatedAt:        time.Now().UTC(),
		})
	}
	log.Printf(
		"agent: 上下文压缩完成(%s) conversation=%s tokens %d → %d（摘要 %d，耗时 %dms，transcript=%s）",
		kind,
		conversationID,
		totalTokens,
		estimateDatabaseMessagesTokens(recent)+estimateTextTokensV2(result.Text),
		estimateTextTokensV2(result.Text),
		result.LatencyMs,
		transcriptPath,
	)
	return nil
}

// recordSummaryInjection 记录摘要中命中的注入特征（只在实际压缩时写审计，避免每轮刷屏）。
func (s *Service) recordSummaryInjection(
	ctx context.Context,
	conversationID string,
	patterns []string,
) {
	if s.db == nil || len(patterns) == 0 {
		return
	}
	_ = s.db.AddInjectionEvent(ctx, database.InjectionEvent{
		ID:             randomID(),
		ConversationID: conversationID,
		SourceType:     "summary",
		SourceID:       conversationID,
		Patterns:       strings.Join(patterns, ","),
		Action:         "flagged",
		CreatedAt:      time.Now().UTC(),
	})
}

func normalizeCompactionKind(kind string) string {
	if strings.EqualFold(strings.TrimSpace(kind), compactionKindMajor) {
		return compactionKindMajor
	}
	return compactionKindMinor
}

// nextCompactionKind 决定本次压缩级别：首次或每 N 次做 major，摘要本身偏大也做 major。
func (s *Service) nextCompactionKind(ctx context.Context, conversationID string) string {
	stored, err := s.db.GetConversationSummary(ctx, conversationID)
	if err != nil || stored == nil || stored.Version <= 0 {
		return compactionKindMajor
	}
	if stored.Version%compactionMajorEveryN == 0 {
		return compactionKindMajor
	}
	budget := s.contextBudgetTokens()
	if budget > 0 && stored.TokenAfter > budget/4 {
		return compactionKindMajor
	}
	return compactionKindMinor
}

// readRecentTranscripts 读取最近 N 份压缩原文，用于 major 重写时避免只依赖旧摘要。
func (s *Service) readRecentTranscripts(conversationID string, limit int) string {
	dir := s.transcriptDir(conversationID)
	if dir == "" || limit <= 0 {
		return ""
	}
	matches, err := filepath.Glob(filepath.Join(dir, "transcript-*.txt"))
	if err != nil || len(matches) == 0 {
		return ""
	}
	sort.Strings(matches)
	if len(matches) > limit {
		matches = matches[len(matches)-limit:]
	}
	var builder strings.Builder
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		builder.Write(raw)
		builder.WriteString("\n")
		if len([]rune(builder.String())) > transcriptReseedRunes {
			break
		}
	}
	return truncateMessageContent(builder.String(), transcriptReseedRunes)
}

// maybeCompactAsync 在请求结束后异步触发压缩：带冷却与超时，失败不影响用户请求。
func (s *Service) maybeCompactAsync(conversationID, userID string) {
	if s == nil || s.db == nil || strings.TrimSpace(conversationID) == "" {
		return
	}
	kind, ok := s.reserveCompaction(conversationID)
	if !ok {
		return
	}

	s.backgroundWG.Add(1)
	go func() {
		defer s.backgroundWG.Done()
		defer s.releaseCompaction(conversationID)
		ctx, cancel := context.WithTimeout(context.Background(), compactionTimeout)
		defer cancel()
		if err := s.compactConversation(ctx, conversationID, userID, kind); err != nil {
			log.Printf("agent: 后台压缩(%s)失败 conversation=%s: %v", kind, conversationID, err)
		}
		embedCtx, embedCancel := context.WithTimeout(context.Background(), memoryEmbeddingBackfillTimeout)
		defer embedCancel()
		s.backfillMemoryEmbeddings(embedCtx, conversationID, userID)
	}()
}

func (s *Service) WaitForBackgroundTasks(timeout time.Duration) bool {
	if s == nil {
		return true
	}
	done := make(chan struct{})
	go func() {
		s.backgroundWG.Wait()
		close(done)
	}()
	if timeout <= 0 {
		<-done
		return true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// reserveCompaction 判定压缩级别并同时执行冷却与在途互斥，避免同一会话重复压缩。
func (s *Service) reserveCompaction(conversationID string) (string, bool) {
	s.compactMu.Lock()
	defer s.compactMu.Unlock()
	if s.compactLast == nil {
		s.compactLast = map[string]time.Time{}
	}
	if s.compactRunning == nil {
		s.compactRunning = map[string]bool{}
	}
	if s.compactRunning[conversationID] {
		return "", false
	}
	kind := s.nextCompactionKind(context.Background(), conversationID)
	cooldown := compactionMinorCooldown
	if kind == compactionKindMajor {
		cooldown = compactionMajorCooldown
	}
	slot := conversationID + "|" + kind
	last := s.compactLast[slot]
	if !last.IsZero() && time.Since(last) < cooldown {
		return "", false
	}
	s.compactLast[slot] = time.Now()
	s.compactRunning[conversationID] = true
	return kind, true
}

func (s *Service) releaseCompaction(conversationID string) {
	s.compactMu.Lock()
	if s.compactRunning != nil {
		delete(s.compactRunning, conversationID)
	}
	s.compactMu.Unlock()
}

// backfillMemoryEmbeddings 为缺失向量的事实补齐 embedding（每次最多 20 条，best-effort）。
// mock/未配置 embedding 时 Embed 直接报错，此处静默跳过，检索继续走关键词+重要度+时间衰减。
func (s *Service) backfillMemoryEmbeddings(ctx context.Context, conversationID, userID string) {
	if s == nil || s.db == nil || s.knowledge == nil {
		return
	}
	conversation, err := s.db.GetConversation(ctx, conversationID, userID)
	if err != nil || strings.TrimSpace(conversation.ProjectID) == "" {
		return
	}
	facts, err := s.db.ListProjectFactEmbeddingCandidates(ctx, conversation.ProjectID, 20)
	if err != nil || len(facts) == 0 {
		return
	}
	texts := make([]string, 0, len(facts))
	for _, fact := range facts {
		texts = append(texts, projectFactSummary(fact))
	}
	vectors, err := s.knowledge.Embed(ctx, texts)
	if err != nil || len(vectors) != len(facts) {
		return
	}
	model := s.knowledge.Mode()
	for index, fact := range facts {
		vector := vectors[index]
		if len(vector) == 0 {
			continue
		}
		if err := s.db.UpdateProjectFactEmbedding(ctx, fact.ID, model, encodeEmbedding(vector)); err != nil {
			log.Printf("agent: 记忆向量回填失败 fact=%s: %v", fact.ID, err)
			return
		}
	}
}
