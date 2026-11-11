package agent

import (
	"context"
	"strings"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

type missionScope struct {
	Hosts            []string
	AssetIDs         []string
	AuthorizedScopes []string
	Active           bool
}

func extractMissionHosts(text string) []string {
	hosts := map[string]bool{}
	for _, host := range probeHostPattern.FindAllString(text, -1) {
		host = strings.ToLower(strings.TrimSpace(host))
		if host != "" {
			hosts[host] = true
		}
	}
	for _, host := range probeIPPattern.FindAllString(text, -1) {
		host = strings.ToLower(strings.TrimSpace(host))
		if host != "" {
			hosts[host] = true
		}
	}
	return limitedSortedKeys(hosts, 12)
}

func (s *Service) missionScopeForConversation(ctx context.Context, conversationID string) missionScope {
	scope := missionScope{}
	if s == nil || s.db == nil || strings.TrimSpace(conversationID) == "" {
		return scope
	}
	userID := strings.TrimSpace(execctx.UserID(ctx))
	conversation, err := s.db.GetConversation(ctx, conversationID, userID)
	if err != nil {
		conversation = nil
	}
	texts := make([]string, 0, 2)
	if conversation != nil {
		texts = append(texts, conversation.Title)
		if strings.TrimSpace(conversation.AssetID) != "" {
			scope.AssetIDs = append(scope.AssetIDs, strings.TrimSpace(conversation.AssetID))
		}
	}
	if messages, messageErr := s.db.GetMessages(ctx, conversationID, 20); messageErr == nil {
		for index := len(messages) - 1; index >= 0; index-- {
			if strings.EqualFold(strings.TrimSpace(messages[index].Role), "user") {
				texts = append(texts, messages[index].Content)
				break
			}
		}
	}
	scope.Hosts = extractMissionHosts(strings.Join(texts, "\n"))
	if len(scope.Hosts) == 0 && len(scope.AssetIDs) == 0 {
		return scope
	}
	scope.Active = true
	projectID := strings.TrimSpace(execctx.ProjectID(ctx))
	if projectID == "" && conversation != nil {
		projectID = strings.TrimSpace(conversation.ProjectID)
	}
	assets, err := s.db.ListProjectAssets(ctx, projectID, userID)
	if err == nil {
		for _, asset := range assets {
			value := strings.ToLower(strings.TrimSpace(asset.Value))
			name := strings.ToLower(strings.TrimSpace(asset.Name))
			for _, host := range scope.Hosts {
				if strings.Contains(value, host) || strings.Contains(name, host) {
					scope.AssetIDs = append(scope.AssetIDs, asset.ID)
					break
				}
			}
		}
	}
	assetSet := map[string]bool{}
	for _, assetID := range scope.AssetIDs {
		if strings.TrimSpace(assetID) != "" {
			assetSet[assetID] = true
		}
	}
	scope.AssetIDs = limitedSortedKeys(assetSet, 0)
	return scope
}

func (scope missionScope) IncludesAsset(assetID string) bool {
	if !scope.Active {
		return true
	}
	assetID = strings.TrimSpace(assetID)
	if assetID != "" {
		for _, candidate := range scope.AssetIDs {
			if candidate == assetID {
				return true
			}
		}
	}
	return false
}

func (scope missionScope) IncludesNode(node database.GraphNode) bool {
	if !scope.Active {
		return true
	}
	if scope.IncludesAsset(node.AssetID) && strings.TrimSpace(node.AssetID) != "" {
		return true
	}
	text := strings.ToLower(strings.Join([]string{
		node.Title,
		node.Detail,
		node.SourceRefID,
	}, "\n"))
	for _, host := range scope.Hosts {
		if strings.Contains(text, host) {
			return true
		}
	}
	return false
}

func (scope missionScope) IncludesText(text string) bool {
	if !scope.Active {
		return true
	}
	text = strings.ToLower(text)
	for _, host := range scope.Hosts {
		if strings.Contains(text, host) {
			return true
		}
	}
	return false
}
