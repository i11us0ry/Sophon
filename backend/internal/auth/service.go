package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"sophon/internal/database"

	"golang.org/x/crypto/bcrypt"
)

const (
	SessionCookieName = "sophon_session"
	CSRFCookieName    = "sophon_csrf"
	CSRFHeaderName    = "X-CSRF-Token"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
)

type Service struct {
	db                     *database.DB
	sessionDuration        time.Duration
	cookieSecure           bool
	bootstrapAdminUsername string
	bootstrapAdminPassword string
}

type LoginResult struct {
	User      *database.User
	Token     string
	CSRFToken string
	ExpiresAt time.Time
}

type AuthenticatedSession struct {
	User      *database.User
	Session   *database.Session
	RawToken  string
	CSRFToken string
}

func NewService(
	db *database.DB,
	sessionDuration time.Duration,
	cookieSecure bool,
	bootstrapAdminUsername string,
	bootstrapAdminPassword string,
) *Service {
	if sessionDuration <= 0 {
		sessionDuration = 12 * time.Hour
	}
	if strings.TrimSpace(bootstrapAdminUsername) == "" {
		bootstrapAdminUsername = "admin"
	}
	return &Service{
		db:                     db,
		sessionDuration:        sessionDuration,
		cookieSecure:           cookieSecure,
		bootstrapAdminUsername: strings.TrimSpace(bootstrapAdminUsername),
		bootstrapAdminPassword: bootstrapAdminPassword,
	}
}

func (s *Service) SessionDuration() time.Duration {
	return s.sessionDuration
}

func (s *Service) CookieSecure() bool {
	return s.cookieSecure
}

// Bootstrap creates the initial administrator only when the user table is empty.
func (s *Service) Bootstrap(ctx context.Context) (string, error) {
	count, err := s.db.CountUsers(ctx)
	if err != nil {
		return "", fmt.Errorf("count users: %w", err)
	}
	if count > 0 {
		return "", nil
	}

	password := strings.TrimSpace(s.bootstrapAdminPassword)
	if password == "" {
		password, err = randomToken(18)
		if err != nil {
			return "", err
		}
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash bootstrap password: %w", err)
	}

	userID, err := randomToken(16)
	if err != nil {
		return "", err
	}
	if err := s.db.CreateUser(ctx, database.User{
		ID:           userID,
		Username:     s.bootstrapAdminUsername,
		PasswordHash: string(passwordHash),
		Role:         "admin",
		Enabled:      true,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		return "", err
	}

	return password, nil
}

func (s *Service) Login(
	ctx context.Context,
	username string,
	password string,
) (*LoginResult, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	user, err := s.db.GetUserByUsername(ctx, username)
	if err != nil {
		if database.IsNoRows(err) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if !user.Enabled {
		return nil, ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	token, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	csrfToken, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	sessionID, err := randomToken(16)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(s.sessionDuration)
	if err := s.db.CreateSession(ctx, database.Session{
		ID:         sessionID,
		UserID:     user.ID,
		TokenHash:  hashToken(token),
		CSRFHash:   hashToken(csrfToken),
		ExpiresAt:  expiresAt,
		CreatedAt:  now,
		LastSeenAt: now,
	}); err != nil {
		return nil, err
	}

	return &LoginResult{
		User:      user,
		Token:     token,
		CSRFToken: csrfToken,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Service) Authenticate(
	ctx context.Context,
	token string,
) (*AuthenticatedSession, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, ErrUnauthorized
	}

	session, user, err := s.db.GetSession(ctx, hashToken(token))
	if err != nil {
		if database.IsNoRows(err) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}

	now := time.Now().UTC()
	if !user.Enabled || !session.ExpiresAt.After(now) {
		_ = s.db.DeleteSession(ctx, session.TokenHash)
		return nil, ErrUnauthorized
	}
	_ = s.db.TouchSession(ctx, session.ID, now)

	return &AuthenticatedSession{
		User:      user,
		Session:   session,
		RawToken:  token,
		CSRFToken: "",
	}, nil
}

func (s *Service) ValidateCSRF(authSession *AuthenticatedSession, token string) bool {
	if authSession == nil || authSession.Session == nil {
		return false
	}
	provided := strings.TrimSpace(token)
	if provided == "" {
		return false
	}
	return subtleCompare(hashToken(provided), authSession.Session.CSRFHash)
}

func (s *Service) Logout(ctx context.Context, rawToken string) error {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil
	}
	return s.db.DeleteSession(ctx, hashToken(rawToken))
}

// ChangePassword 校验当前密码与复杂度后更新密码，并注销该用户的其他会话。
func (s *Service) ChangePassword(
	ctx context.Context,
	userID string,
	rawToken string,
	currentPassword string,
	newPassword string,
) error {
	if strings.TrimSpace(userID) == "" {
		return ErrUnauthorized
	}
	user, err := s.db.GetUserByID(ctx, userID)
	if err != nil {
		return ErrUnauthorized
	}
	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.PasswordHash),
		[]byte(currentPassword),
	); err != nil {
		return ErrInvalidCredentials
	}
	if currentPassword == newPassword {
		return fmt.Errorf("新密码不能与当前密码相同")
	}
	if err := ValidatePasswordStrength(newPassword); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := s.db.UpdateUserPassword(ctx, userID, string(hash)); err != nil {
		return err
	}
	if token := strings.TrimSpace(rawToken); token != "" {
		_ = s.db.DeleteOtherSessions(ctx, userID, hashToken(token))
	}
	return nil
}

// ValidatePasswordStrength 要求至少 8 位，且包含大写/小写/数字/符号中的至少三类。
func ValidatePasswordStrength(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("新密码长度至少 8 位")
	}
	if len(password) > 256 {
		return fmt.Errorf("新密码长度不能超过 256 位")
	}
	classes := 0
	if strings.ContainsFunc(password, unicode.IsLower) {
		classes++
	}
	if strings.ContainsFunc(password, unicode.IsUpper) {
		classes++
	}
	if strings.ContainsFunc(password, unicode.IsDigit) {
		classes++
	}
	if strings.ContainsFunc(password, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		classes++
	}
	if classes < 3 {
		return fmt.Errorf("新密码需包含大写字母、小写字母、数字、符号中的至少三类")
	}
	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return hex.EncodeToString(sum[:])
}

func randomToken(byteLength int) (string, error) {
	buffer := make([]byte, byteLength)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate secure token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func subtleCompare(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	var diff byte
	for i := 0; i < len(left); i++ {
		diff |= left[i] ^ right[i]
	}
	return diff == 0
}
