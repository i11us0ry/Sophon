package rbac

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"sophon/internal/database"

	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	db *database.DB
}

type UserInput struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Password    string `json:"password"`
	Role        string `json:"role"`
	Enabled     bool   `json:"enabled"`
}

type RoleInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

func NewService(db *database.DB) *Service {
	return &Service{db: db}
}

func (s *Service) Seed(ctx context.Context) error {
	roles := []database.RBACRole{
		{
			Name:        "admin",
			Description: "系统管理员",
			Permissions: []string{"*"},
			Builtin:     true,
		},
		{
			Name:        "operator",
			Description: "安全测试操作员",
			Permissions: operatorPermissions(),
			Builtin:     true,
		},
		{
			Name:        "viewer",
			Description: "只读用户",
			Permissions: readPermissions(),
			Builtin:     true,
		},
	}
	for _, role := range roles {
		if err := s.db.UpsertRBACRole(ctx, role); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) HasPermission(
	ctx context.Context,
	user *database.User,
	permission string,
) bool {
	if user == nil || !user.Enabled {
		return false
	}
	role, err := s.db.GetRBACRole(ctx, user.Role)
	if err != nil {
		return user.Role == "admin"
	}
	for _, item := range role.Permissions {
		if item == "*" || item == permission {
			return true
		}
	}
	return false
}

func (s *Service) ListRoles(ctx context.Context) ([]database.RBACRole, error) {
	return s.db.ListRBACRoles(ctx)
}

func (s *Service) CreateRole(ctx context.Context, input RoleInput) error {
	input.Name = normalizeName(input.Name)
	if input.Name == "" {
		return fmt.Errorf("角色名称不能为空")
	}
	if _, err := s.db.GetRBACRole(ctx, input.Name); err == nil {
		return fmt.Errorf("角色已存在")
	}
	return s.db.UpsertRBACRole(ctx, database.RBACRole{
		Name:        input.Name,
		Description: strings.TrimSpace(input.Description),
		Permissions: normalizePermissions(input.Permissions),
	})
}

func (s *Service) UpdateRole(ctx context.Context, name string, input RoleInput) error {
	name = normalizeName(name)
	role, err := s.db.GetRBACRole(ctx, name)
	if err != nil {
		return err
	}
	role.Description = strings.TrimSpace(input.Description)
	role.Permissions = normalizePermissions(input.Permissions)
	return s.db.UpsertRBACRole(ctx, *role)
}

func (s *Service) DeleteRole(ctx context.Context, name string) error {
	name = normalizeName(name)
	role, err := s.db.GetRBACRole(ctx, name)
	if err != nil {
		return err
	}
	if role.Builtin {
		return fmt.Errorf("内置角色不能删除")
	}
	count, err := s.db.CountUsersWithRole(ctx, name)
	if err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("角色仍被用户使用")
	}
	return s.db.DeleteRBACRole(ctx, name)
}

func (s *Service) ListUsers(ctx context.Context) ([]database.User, error) {
	return s.db.ListUsers(ctx)
}

func (s *Service) CreateUser(ctx context.Context, input UserInput) (*database.User, error) {
	input.Username = strings.ToLower(strings.TrimSpace(input.Username))
	input.Role = normalizeName(input.Role)
	if input.Username == "" || len(input.Username) > 64 {
		return nil, fmt.Errorf("用户名不合法")
	}
	if len(input.Password) < 8 || len(input.Password) > 256 {
		return nil, fmt.Errorf("密码长度必须为 8 到 256 位")
	}
	if _, err := s.db.GetRBACRole(ctx, input.Role); err != nil {
		return nil, fmt.Errorf("角色不存在")
	}
	if _, err := s.db.GetUserByUsername(ctx, input.Username); err == nil {
		return nil, fmt.Errorf("用户名已存在")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	user := database.User{
		ID:           newID(),
		Username:     input.Username,
		DisplayName:  strings.TrimSpace(input.DisplayName),
		PasswordHash: string(hash),
		Role:         input.Role,
		Enabled:      input.Enabled,
		CreatedAt:    time.Now().UTC(),
	}
	if err := s.db.CreateUser(ctx, user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Service) UpdateUser(
	ctx context.Context,
	actorID string,
	userID string,
	input UserInput,
) error {
	user, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if actorID == userID {
		if !input.Enabled {
			return fmt.Errorf("不能禁用当前登录账号")
		}
		if next := normalizeName(input.Role); next != "" && next != user.Role {
			return fmt.Errorf("不能修改当前登录账号的角色")
		}
	}
	if user.Enabled && !input.Enabled && user.Role == "admin" {
		if err := s.ensureAnotherEnabledAdmin(ctx); err != nil {
			return err
		}
	}
	if input.Role != "" {
		nextRole := normalizeName(input.Role)
		if _, err := s.db.GetRBACRole(ctx, nextRole); err != nil {
			return fmt.Errorf("角色不存在")
		}
		if user.Enabled && user.Role == "admin" && nextRole != "admin" {
			if err := s.ensureAnotherEnabledAdmin(ctx); err != nil {
				return err
			}
		}
		user.Role = nextRole
	}
	displayName := user.DisplayName
	if input.DisplayName != "" {
		displayName = strings.TrimSpace(input.DisplayName)
	}
	if err := s.db.UpdateUser(ctx, userID, displayName, user.Role, input.Enabled); err != nil {
		return err
	}
	if input.Password != "" {
		if len(input.Password) < 8 || len(input.Password) > 256 {
			return fmt.Errorf("密码长度必须为 8 到 256 位")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		if err := s.db.UpdateUserPassword(ctx, userID, string(hash)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) DeleteUser(ctx context.Context, actorID, userID string) error {
	user, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if actorID != "" && actorID == userID {
		return fmt.Errorf("不能删除当前登录账号")
	}
	if strings.EqualFold(user.Username, "admin") {
		return fmt.Errorf("内置管理员不能删除")
	}
	if user.Enabled && user.Role == "admin" {
		if err := s.ensureAnotherEnabledAdmin(ctx); err != nil {
			return err
		}
	}
	return s.db.DeleteUser(ctx, userID)
}

func (s *Service) ensureAnotherEnabledAdmin(ctx context.Context) error {
	count, err := s.db.CountEnabledAdmins(ctx)
	if err != nil {
		return err
	}
	if count <= 1 {
		return fmt.Errorf("至少需要保留一个启用的管理员")
	}
	return nil
}

func PermissionCatalog() map[string][]string {
	return map[string][]string{
		"dashboard":     {"dashboard:read"},
		"chat":          {"chat:read", "chat:write", "chat:delete"},
		"agent":         {"agent:execute"},
		"tasks":         {"tasks:read", "tasks:write"},
		"agentRole":     {"agentRole:read", "agentRole:admin"},
		"zhizi":         {"zhizi:read", "zhizi:execute", "zhizi:write", "zhizi:delete"},
		"mcp":           {"mcp:read", "mcp:write", "mcp:delete"},
		"project":       {"project:read", "project:write", "project:delete"},
		"asset":         {"asset:read", "asset:write", "asset:delete"},
		"vulnerability": {"vulnerability:read", "vulnerability:write", "vulnerability:delete"},
		"knowledge":     {"knowledge:read", "knowledge:write", "knowledge:delete"},
		"skills":        {"skills:read", "skills:write", "skills:delete"},
		"webshell":      {"webshell:read", "webshell:write", "webshell:delete"},
		"hitl":          {"hitl:read", "hitl:write"},
		"audit":         {"audit:read", "audit:delete"},
		"monitor":       {"monitor:read", "monitor:write", "monitor:delete"},
		"config":        {"config:read", "config:write"},
		"rbac":          {"rbac:read", "rbac:write"},
		"settings":      {"settings:read", "settings:write"},
	}
}

func operatorPermissions() []string {
	result := []string{
		"dashboard:read",
		"chat:read", "chat:write", "chat:delete",
		"agent:execute",
		"tasks:read", "tasks:write",
		"agentRole:read",
		"zhizi:read", "zhizi:execute",
		"mcp:read", "mcp:write", "mcp:delete",
		"project:read", "project:write", "project:delete",
		"asset:read", "asset:write", "asset:delete",
		"vulnerability:read", "vulnerability:write", "vulnerability:delete",
		"knowledge:read", "knowledge:write", "knowledge:delete",
		"skills:read", "skills:write", "skills:delete",
		"webshell:read", "webshell:write", "webshell:delete",
		"hitl:read", "hitl:write",
		"audit:read",
		"monitor:read", "monitor:write", "monitor:delete",
		"settings:read",
	}
	sort.Strings(result)
	return result
}

func readPermissions() []string {
	result := []string{
		"dashboard:read",
		"chat:read",
		"project:read",
		"asset:read",
		"vulnerability:read",
		"knowledge:read",
		"skills:read",
		"webshell:read",
		"hitl:read",
		"audit:read",
		"monitor:read",
		"agentRole:read",
		"zhizi:read",
		"mcp:read",
		"settings:read",
	}
	sort.Strings(result)
	return result
}

func normalizePermissions(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func normalizeName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func newID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("id_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}
