package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sophon/internal/execctx"
	"sophon/internal/skillname"

	"github.com/cloudwego/eino/components/tool"
)

const (
	readSkillToolName = "read_skill"
	readSkillMaxRunes = 20000
)

// newSkillReaderTool 构造只读技能工具：按技能名读取 skills_dir/<name>/SKILL.md。
// 该工具不进入默认 HITL 清单，模型可按需加载技能正文而不触发人工审批。
func newSkillReaderTool(service *Service) tool.BaseTool {
	return &singleStringTool{
		name:      readSkillToolName,
		desc:      "按需读取指定技能正文作为启发式参考。仅在没有成果、成果不理想、没有下一步思路或方向停滞时使用；技能清单不是必读门禁，也不是漏洞覆盖上限。",
		param:     "name",
		paramDesc: "最相关的技能名称，例如 attack-surface-recon",
		run: func(ctx context.Context, value string) (string, error) {
			name := strings.TrimSpace(value)
			if !skillname.Valid(name) {
				return "", fmt.Errorf("技能名称不合法: %q", name)
			}
			if allowed, restricted := service.roleSkillAccess(ctx, name); restricted && !allowed {
				return "", fmt.Errorf("技能 %s 未绑定到当前角色", name)
			}
			skillsDir := strings.TrimSpace(service.configSnapshot().SkillsDir)
			if skillsDir == "" {
				return "", fmt.Errorf("未配置技能目录 skills_dir")
			}
			raw, err := os.ReadFile(filepath.Join(skillsDir, name, "SKILL.md"))
			if err != nil {
				return "", fmt.Errorf("读取技能 %s 失败: %w", name, err)
			}
			content := strings.TrimSpace(string(raw))
			if content == "" {
				return "", fmt.Errorf("技能 %s 内容为空", name)
			}
			if info, ok := execctx.Subagent(ctx); ok && info.SkillGate != nil {
				info.SkillGate.MarkLoaded(name)
			}
			runes := []rune(content)
			if len(runes) > readSkillMaxRunes {
				return string(runes[:readSkillMaxRunes]) + "\n\n[内容已截断]", nil
			}
			return content, nil
		},
	}
}

func (s *Service) roleSkillAccess(ctx context.Context, skillName string) (bool, bool) {
	if s == nil || s.db == nil {
		return false, true
	}
	if info, ok := execctx.Subagent(ctx); ok && len(info.AllowedSkills) > 0 {
		allowed := false
		for _, name := range info.AllowedSkills {
			if strings.TrimSpace(name) == skillName {
				allowed = true
				break
			}
		}
		if !allowed {
			return false, true
		}
	}
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	userID := strings.TrimSpace(execctx.UserID(ctx))
	if conversationID == "" || userID == "" {
		return false, true
	}
	conversation, err := s.db.GetConversation(ctx, conversationID, userID)
	if err != nil {
		return false, true
	}
	if strings.TrimSpace(conversation.AgentRoleID) == "" {
		return false, false
	}
	role, err := s.db.GetAgentRole(ctx, conversation.AgentRoleID)
	if err != nil || !role.Enabled || len(role.Skills) == 0 {
		return false, true
	}
	for _, bound := range role.Skills {
		if strings.TrimSpace(bound) == skillName {
			return true, true
		}
	}
	return false, true
}
