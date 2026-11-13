package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrZhiziNoCapacity               = errors.New("没有可用的智子分身")
	ErrZhiziConversationDisabled     = errors.New("当前对话未启用智子分身")
	ErrZhiziConversationUnauthorized = errors.New("对话不存在或无权访问")
	ErrZhiziNodeInUse                = errors.New("智子分身仍有任务占用")
	ErrZhiziNodeInitializing         = errors.New("智子分身正在初始化")
)

type ZhiziNode struct {
	ID                 string    `json:"id"`
	CreatedByUserID    string    `json:"createdByUserId"`
	Name               string    `json:"name"`
	Host               string    `json:"host"`
	Port               int       `json:"port"`
	Username           string    `json:"username"`
	AuthType           string    `json:"authType"`
	HostKeyFingerprint string    `json:"hostKeyFingerprint"`
	WorkRoot           string    `json:"workRoot"`
	MaxSlots           int       `json:"maxSlots"`
	ActiveSlots        int       `json:"activeSlots"`
	Enabled            bool      `json:"enabled"`
	LastTestAt         time.Time `json:"lastTestAt"`
	LastTestError      string    `json:"lastTestError"`
	InitStatus         string    `json:"initStatus"`
	InitMessage        string    `json:"initMessage"`
	InitStartedAt      time.Time `json:"initStartedAt"`
	InitFinishedAt     time.Time `json:"initFinishedAt"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

type ZhiziNodeSecret struct {
	Password   string
	PrivateKey string
}

type ZhiziLease struct {
	ID             string    `json:"id"`
	NodeID         string    `json:"nodeId"`
	OwnerUserID    string    `json:"ownerUserId"`
	ConversationID string    `json:"conversationId"`
	Status         string    `json:"status"`
	ExpiresAt      time.Time `json:"expiresAt"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
	Node           ZhiziNode `json:"node"`
}

type ZhiziConversationState struct {
	Enabled bool        `json:"enabled"`
	Lease   *ZhiziLease `json:"lease,omitempty"`
}

type ZhiziAvailability struct {
	EnabledNodes int `json:"enabledNodes"`
	TotalSlots   int `json:"totalSlots"`
	ActiveSlots  int `json:"activeSlots"`
	Available    int `json:"available"`
}

func (db *DB) CreateZhiziNode(
	ctx context.Context,
	node ZhiziNode,
	secret ZhiziNodeSecret,
) (*ZhiziNode, error) {
	items, err := db.CreateZhiziNodes(ctx, []ZhiziNode{node}, secret)
	if err != nil {
		return nil, err
	}
	return &items[0], nil
}

func (db *DB) CreateZhiziNodes(
	ctx context.Context,
	nodes []ZhiziNode,
	secret ZhiziNodeSecret,
) ([]ZhiziNode, error) {
	if len(nodes) == 0 {
		return []ZhiziNode{}, nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	ids := make([]string, 0, len(nodes))
	for index := range nodes {
		node := &nodes[index]
		if strings.TrimSpace(node.ID) == "" {
			node.ID = newID()
		}
		passwordCipher, err := db.encryptZhiziSecret(secret.Password)
		if err != nil {
			return nil, err
		}
		privateKeyCipher, err := db.encryptZhiziSecret(secret.PrivateKey)
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO zhizi_nodes (
				id, created_by_user_id, name, host, port, username, auth_type,
				password_cipher, private_key_cipher, host_key_fingerprint, work_root,
				max_slots, enabled, last_test_at, last_test_error, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?, ?)`,
			node.ID,
			node.CreatedByUserID,
			node.Name,
			node.Host,
			node.Port,
			node.Username,
			node.AuthType,
			passwordCipher,
			privateKeyCipher,
			node.HostKeyFingerprint,
			node.WorkRoot,
			node.MaxSlots,
			boolToInt(node.Enabled),
			now.Unix(),
			now.Unix(),
		); err != nil {
			return nil, fmt.Errorf("create zhizi node: %w", err)
		}
		ids = append(ids, node.ID)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	items := make([]ZhiziNode, 0, len(ids))
	for _, id := range ids {
		item, err := db.GetZhiziNode(ctx, id)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	return items, nil
}

func (db *DB) UpdateZhiziNode(
	ctx context.Context,
	node ZhiziNode,
	secret ZhiziNodeSecret,
) (*ZhiziNode, error) {
	passwordCipher, err := db.encryptZhiziSecret(secret.Password)
	if err != nil {
		return nil, err
	}
	privateKeyCipher, err := db.encryptZhiziSecret(secret.PrivateKey)
	if err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	lockResult, err := tx.ExecContext(
		ctx,
		`UPDATE zhizi_nodes SET updated_at = updated_at WHERE id = ?`,
		node.ID,
	)
	if err := requireAffected(lockResult, err); err != nil {
		return nil, err
	}
	var currentHost, currentUsername, currentAuthType string
	var currentFingerprint, currentWorkRoot, currentInitStatus string
	var currentPort int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT host, port, username, auth_type, host_key_fingerprint, work_root, init_status
		 FROM zhizi_nodes WHERE id = ?`,
		node.ID,
	).Scan(
		&currentHost,
		&currentPort,
		&currentUsername,
		&currentAuthType,
		&currentFingerprint,
		&currentWorkRoot,
		&currentInitStatus,
	); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var activeSlots int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM zhizi_leases
		 WHERE node_id = ? AND status = 'active' AND expires_at > ?`,
		node.ID,
		now.Unix(),
	).Scan(&activeSlots); err != nil {
		return nil, err
	}
	if activeSlots > 0 {
		return nil, ErrZhiziNodeInUse
	}
	if currentInitStatus == "queued" || currentInitStatus == "running" {
		return nil, ErrZhiziNodeInitializing
	}
	connectionChanged := currentHost != node.Host ||
		currentPort != node.Port ||
		currentUsername != node.Username ||
		currentAuthType != node.AuthType ||
		currentFingerprint != node.HostKeyFingerprint ||
		currentWorkRoot != node.WorkRoot
	credentialsChanged := strings.TrimSpace(secret.Password) != "" ||
		strings.TrimSpace(secret.PrivateKey) != ""
	result, err := tx.ExecContext(
		ctx,
		`UPDATE zhizi_nodes SET
			name = ?, host = ?, port = ?, username = ?, auth_type = ?,
			password_cipher = CASE
				WHEN ? = 'key' THEN ''
				WHEN ? = '' THEN password_cipher
				ELSE ? END,
			private_key_cipher = CASE
				WHEN ? = 'password' THEN ''
				WHEN ? = '' THEN private_key_cipher
				ELSE ? END,
			host_key_fingerprint = ?, work_root = ?, max_slots = ?, enabled = ?, updated_at = ?
		 WHERE id = ?`,
		node.Name,
		node.Host,
		node.Port,
		node.Username,
		node.AuthType,
		node.AuthType,
		passwordCipher,
		passwordCipher,
		node.AuthType,
		privateKeyCipher,
		privateKeyCipher,
		node.HostKeyFingerprint,
		node.WorkRoot,
		node.MaxSlots,
		boolToInt(node.Enabled),
		now.Unix(),
		node.ID,
	)
	if err := requireAffected(result, err); err != nil {
		return nil, err
	}
	if !node.Enabled {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE zhizi_leases SET status = 'released', updated_at = ?
			 WHERE node_id = ? AND status = 'active'`,
			now.Unix(),
			node.ID,
		); err != nil {
			return nil, err
		}
	}
	if connectionChanged || credentialsChanged {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE zhizi_nodes SET last_test_at = 0, last_test_error = '', updated_at = ?
			 WHERE id = ?`,
			now.Unix(),
			node.ID,
		); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetZhiziNode(ctx, node.ID)
}

func (db *DB) GetZhiziNode(ctx context.Context, id string) (*ZhiziNode, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT n.id, n.created_by_user_id, n.name, n.host, n.port, n.username,
			n.auth_type, n.host_key_fingerprint, n.work_root, n.max_slots, n.enabled,
			n.last_test_at, n.last_test_error,
			n.init_status, n.init_message, n.init_started_at, n.init_finished_at,
			n.created_at, n.updated_at,
			(SELECT COUNT(*) FROM zhizi_leases l
			 WHERE l.node_id = n.id AND l.status = 'active' AND l.expires_at > ?) AS active_slots
		 FROM zhizi_nodes n WHERE n.id = ?`,
		time.Now().UTC().Unix(),
		id,
	)
	item, err := scanZhiziNode(row)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) ListZhiziNodes(ctx context.Context) ([]ZhiziNode, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT n.id, n.created_by_user_id, n.name, n.host, n.port, n.username,
			n.auth_type, n.host_key_fingerprint, n.work_root, n.max_slots, n.enabled,
			n.last_test_at, n.last_test_error,
			n.init_status, n.init_message, n.init_started_at, n.init_finished_at,
			n.created_at, n.updated_at,
			(SELECT COUNT(*) FROM zhizi_leases l
			 WHERE l.node_id = n.id AND l.status = 'active' AND l.expires_at > ?) AS active_slots
		 FROM zhizi_nodes n
		 ORDER BY n.enabled DESC, n.name ASC`,
		time.Now().UTC().Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ZhiziNode, 0)
	for rows.Next() {
		item, err := scanZhiziNode(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) GetZhiziNodeSecret(ctx context.Context, id string) (*ZhiziNode, ZhiziNodeSecret, error) {
	node, err := db.GetZhiziNode(ctx, id)
	if err != nil {
		return nil, ZhiziNodeSecret{}, err
	}
	var passwordCipher, privateKeyCipher string
	if err := db.QueryRowContext(
		ctx,
		`SELECT password_cipher, private_key_cipher FROM zhizi_nodes WHERE id = ?`,
		id,
	).Scan(&passwordCipher, &privateKeyCipher); err != nil {
		return nil, ZhiziNodeSecret{}, err
	}
	password, err := db.decryptZhiziSecret(passwordCipher)
	if err != nil {
		return nil, ZhiziNodeSecret{}, err
	}
	privateKey, err := db.decryptZhiziSecret(privateKeyCipher)
	if err != nil {
		return nil, ZhiziNodeSecret{}, err
	}
	return node, ZhiziNodeSecret{Password: password, PrivateKey: privateKey}, nil
}

func (db *DB) SetZhiziNodeEnabled(ctx context.Context, id string, enabled bool) error {
	now := time.Now().UTC().Unix()
	result, err := db.ExecContext(
		ctx,
		`UPDATE zhizi_nodes SET enabled = ?, updated_at = ? WHERE id = ?`,
		boolToInt(enabled),
		now,
		id,
	)
	if err := requireAffected(result, err); err != nil {
		return err
	}
	if !enabled {
		_, err = db.ExecContext(
			ctx,
			`UPDATE zhizi_leases SET status = 'released', updated_at = ?
			 WHERE node_id = ? AND status = 'active'`,
			now,
			id,
		)
	}
	return err
}

func (db *DB) RecordZhiziNodeTest(ctx context.Context, id string, testErr error) error {
	message := ""
	if testErr != nil {
		message = testErr.Error()
	}
	result, err := db.ExecContext(
		ctx,
		`UPDATE zhizi_nodes SET last_test_at = ?, last_test_error = ?, updated_at = ? WHERE id = ?`,
		time.Now().UTC().Unix(),
		truncateDatabaseText(message, 500),
		time.Now().UTC().Unix(),
		id,
	)
	return requireAffected(result, err)
}

func (db *DB) SetZhiziNodeInitQueued(ctx context.Context, id string) error {
	now := time.Now().UTC().Unix()
	result, err := db.ExecContext(
		ctx,
		`UPDATE zhizi_nodes SET
			init_status = 'queued', init_message = '', init_started_at = 0,
			init_finished_at = 0, updated_at = ?
		 WHERE id = ?`,
		now,
		id,
	)
	return requireAffected(result, err)
}

func (db *DB) SetZhiziNodeInitRunning(ctx context.Context, id string) error {
	now := time.Now().UTC().Unix()
	result, err := db.ExecContext(
		ctx,
		`UPDATE zhizi_nodes SET
			init_status = 'running', init_message = '', init_started_at = ?,
			init_finished_at = 0, updated_at = ?
		 WHERE id = ?`,
		now,
		now,
		id,
	)
	return requireAffected(result, err)
}

func (db *DB) FinishZhiziNodeInit(ctx context.Context, id string, success bool, message string) error {
	status := "failed"
	if success {
		status = "succeeded"
	}
	now := time.Now().UTC().Unix()
	result, err := db.ExecContext(
		ctx,
		`UPDATE zhizi_nodes SET
			init_status = ?, init_message = ?, init_finished_at = ?, updated_at = ?
		 WHERE id = ?`,
		status,
		truncateDatabaseText(message, 4000),
		now,
		now,
		id,
	)
	return requireAffected(result, err)
}

func (db *DB) RecoverZhiziNodeInitStatesOnStartup(ctx context.Context) (int64, error) {
	now := time.Now().UTC().Unix()
	result, err := db.ExecContext(
		ctx,
		`UPDATE zhizi_nodes SET
			init_status = 'failed',
			init_message = '服务重启导致初始化中断',
			init_finished_at = ?,
			updated_at = ?
		 WHERE init_status IN ('queued', 'running')`,
		now,
		now,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *DB) DeleteZhiziNodes(ctx context.Context, ids []string) (int64, error) {
	ids = normalizeZhiziIDs(ids)
	if len(ids) == 0 {
		return 0, nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]interface{}, len(ids))
	for index, id := range ids {
		args[index] = id
	}
	lockResult, err := tx.ExecContext(
		ctx,
		`UPDATE zhizi_nodes SET updated_at = updated_at WHERE id IN (`+placeholders+`)`,
		args...,
	)
	if err != nil {
		return 0, err
	}
	if _, err := lockResult.RowsAffected(); err != nil {
		return 0, err
	}
	var activeSlots, initializing int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM zhizi_leases
		 WHERE node_id IN (`+placeholders+`) AND status = 'active' AND expires_at > ?`,
		append(append([]interface{}{}, args...), time.Now().UTC().Unix())...,
	).Scan(&activeSlots); err != nil {
		return 0, err
	}
	if activeSlots > 0 {
		return 0, ErrZhiziNodeInUse
	}
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM zhizi_nodes
		 WHERE id IN (`+placeholders+`) AND init_status IN ('queued', 'running')`,
		args...,
	).Scan(&initializing); err != nil {
		return 0, err
	}
	if initializing > 0 {
		return 0, ErrZhiziNodeInitializing
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM zhizi_leases WHERE node_id IN (`+placeholders+`)`,
		args...,
	); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM zhizi_nodes WHERE id IN (`+placeholders+`)`,
		args...,
	)
	if err != nil {
		return 0, err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
}

func normalizeZhiziIDs(ids []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		result = append(result, id)
	}
	return result
}

func (db *DB) ZhiziAvailability(ctx context.Context) (ZhiziAvailability, error) {
	var result ZhiziAvailability
	err := db.QueryRowContext(
		ctx,
		`SELECT
			COUNT(*),
			COALESCE(SUM(max_slots), 0),
			COALESCE(SUM((SELECT COUNT(*) FROM zhizi_leases l
			 WHERE l.node_id = zhizi_nodes.id AND l.status = 'active' AND l.expires_at > ?)), 0)
		 FROM zhizi_nodes
		 WHERE enabled = 1
		   AND host_key_fingerprint <> ''
		   AND last_test_at > 0
		   AND last_test_error = ''`,
		time.Now().UTC().Unix(),
	).Scan(&result.EnabledNodes, &result.TotalSlots, &result.ActiveSlots)
	if err != nil {
		return result, err
	}
	result.Available = max(0, result.TotalSlots-result.ActiveSlots)
	return result, nil
}

func (db *DB) SetZhiziConversationEnabled(
	ctx context.Context,
	conversationID string,
	ownerUserID string,
	enabled bool,
) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := verifyZhiziConversationTx(ctx, tx, conversationID, ownerUserID); err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO zhizi_conversation_settings (conversation_id, enabled, updated_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT(conversation_id) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at`,
		conversationID,
		boolToInt(enabled),
		now,
	); err != nil {
		return err
	}
	if !enabled {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE zhizi_leases SET status = 'released', updated_at = ?
			 WHERE conversation_id = ? AND owner_user_id = ? AND status = 'active'`,
			now,
			conversationID,
			ownerUserID,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) GetZhiziConversationState(
	ctx context.Context,
	conversationID string,
	ownerUserID string,
) (ZhiziConversationState, error) {
	var enabled int
	err := db.QueryRowContext(
		ctx,
		`SELECT COALESCE(s.enabled, 0)
		 FROM conversations c
		 LEFT JOIN zhizi_conversation_settings s ON s.conversation_id = c.id
		 WHERE c.id = ? AND c.owner_user_id = ?`,
		conversationID,
		ownerUserID,
	).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return ZhiziConversationState{}, ErrZhiziConversationUnauthorized
	}
	if err != nil {
		return ZhiziConversationState{}, err
	}
	state := ZhiziConversationState{Enabled: enabled != 0}
	if state.Enabled {
		lease, err := db.GetActiveZhiziLease(ctx, conversationID, ownerUserID)
		if err != nil {
			return state, err
		}
		state.Lease = lease
	}
	return state, nil
}

func (db *DB) AcquireZhiziLease(
	ctx context.Context,
	conversationID string,
	ownerUserID string,
	ttl time.Duration,
) (*ZhiziLease, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := verifyZhiziConversationTx(ctx, tx, conversationID, ownerUserID); err != nil {
		return nil, err
	}
	var enabled int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COALESCE(enabled, 0) FROM zhizi_conversation_settings WHERE conversation_id = ?`,
		conversationID,
	).Scan(&enabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrZhiziConversationDisabled
		}
		return nil, err
	}
	if enabled == 0 {
		return nil, ErrZhiziConversationDisabled
	}
	now := time.Now().UTC()
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE zhizi_leases SET status = 'expired', updated_at = ?
		 WHERE status = 'active' AND expires_at <= ?`,
		now.Unix(),
		now.Unix(),
	); err != nil {
		return nil, err
	}
	var existingID string
	err = tx.QueryRowContext(
		ctx,
		`SELECT l.id FROM zhizi_leases l
		 WHERE l.conversation_id = ? AND l.owner_user_id = ? AND l.status = 'active'
		   AND EXISTS (
		     SELECT 1 FROM zhizi_nodes n
		     WHERE n.id = l.node_id
		       AND n.enabled = 1
		       AND n.host_key_fingerprint <> ''
		       AND n.last_test_at > 0
		       AND n.last_test_error = ''
		   )
		 ORDER BY l.created_at DESC LIMIT 1`,
		conversationID,
		ownerUserID,
	).Scan(&existingID)
	if err == nil {
		expiresAt := now.Add(ttl)
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE zhizi_leases SET expires_at = ?, updated_at = ? WHERE id = ?`,
			expiresAt.Unix(),
			now.Unix(),
			existingID,
		); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return db.GetActiveZhiziLease(ctx, conversationID, ownerUserID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var nodeID string
	err = tx.QueryRowContext(
		ctx,
		`SELECT n.id
		 FROM zhizi_nodes n
		 LEFT JOIN zhizi_leases l ON l.node_id = n.id AND l.status = 'active' AND l.expires_at > ?
		 WHERE n.enabled = 1
		   AND n.host_key_fingerprint <> ''
		   AND n.last_test_at > 0
		   AND n.last_test_error = ''
		 GROUP BY n.id
		 HAVING COUNT(l.id) < n.max_slots
		 ORDER BY COUNT(l.id) ASC, n.name ASC
		 LIMIT 1`,
		now.Unix(),
	).Scan(&nodeID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrZhiziNoCapacity
	}
	if err != nil {
		return nil, err
	}
	leaseID := newID()
	expiresAt := now.Add(ttl)
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO zhizi_leases (
			id, node_id, owner_user_id, conversation_id, status, expires_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, 'active', ?, ?, ?)`,
		leaseID,
		nodeID,
		ownerUserID,
		conversationID,
		expiresAt.Unix(),
		now.Unix(),
		now.Unix(),
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetActiveZhiziLease(ctx, conversationID, ownerUserID)
}

func (db *DB) GetActiveZhiziLease(
	ctx context.Context,
	conversationID string,
	ownerUserID string,
) (*ZhiziLease, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT l.id, l.node_id, l.owner_user_id, l.conversation_id, l.status,
			l.expires_at, l.created_at, l.updated_at,
			n.id, n.created_by_user_id, n.name, n.host, n.port, n.username,
			n.auth_type, n.host_key_fingerprint, n.work_root, n.max_slots, n.enabled,
			n.last_test_at, n.last_test_error,
			n.init_status, n.init_message, n.init_started_at, n.init_finished_at,
			n.created_at, n.updated_at,
			(SELECT COUNT(*) FROM zhizi_leases active
			 WHERE active.node_id = n.id AND active.status = 'active' AND active.expires_at > ?) AS active_slots
		 FROM zhizi_leases l
		 JOIN zhizi_nodes n ON n.id = l.node_id
		 WHERE l.conversation_id = ? AND l.owner_user_id = ?
		   AND l.status = 'active' AND l.expires_at > ?
		   AND n.enabled = 1
		   AND n.host_key_fingerprint <> ''
		   AND n.last_test_at > 0
		   AND n.last_test_error = ''
		 ORDER BY l.created_at DESC LIMIT 1`,
		time.Now().UTC().Unix(),
		conversationID,
		ownerUserID,
		time.Now().UTC().Unix(),
	)
	lease, err := scanZhiziLease(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &lease, nil
}

func (db *DB) RenewZhiziLease(ctx context.Context, leaseID string, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	now := time.Now().UTC()
	result, err := db.ExecContext(
		ctx,
		`UPDATE zhizi_leases SET expires_at = ?, updated_at = ?
		 WHERE id = ? AND status = 'active'
		   AND EXISTS (
		     SELECT 1 FROM zhizi_nodes n
		     WHERE n.id = zhizi_leases.node_id
		       AND n.enabled = 1
		       AND n.host_key_fingerprint <> ''
		       AND n.last_test_at > 0
		       AND n.last_test_error = ''
		   )`,
		now.Add(ttl).Unix(),
		now.Unix(),
		leaseID,
	)
	return requireAffected(result, err)
}

func (db *DB) ReleaseZhiziLease(ctx context.Context, leaseID string) error {
	result, err := db.ExecContext(
		ctx,
		`UPDATE zhizi_leases SET status = 'released', updated_at = ?
		 WHERE id = ? AND status = 'active'`,
		time.Now().UTC().Unix(),
		leaseID,
	)
	return requireAffected(result, err)
}

func (db *DB) ReleaseZhiziLeaseByConversation(ctx context.Context, conversationID string) error {
	_, err := db.ExecContext(
		ctx,
		`UPDATE zhizi_leases SET status = 'released', updated_at = ?
		 WHERE conversation_id = ? AND status = 'active'`,
		time.Now().UTC().Unix(),
		conversationID,
	)
	return err
}

func (db *DB) RecoverZhiziLeasesOnStartup(ctx context.Context) (int64, error) {
	result, err := db.ExecContext(
		ctx,
		`UPDATE zhizi_leases SET status = 'released', updated_at = ?
		 WHERE status = 'active'`,
		time.Now().UTC().Unix(),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *DB) setZhiziConversationEnabledTx(
	ctx context.Context,
	tx *sql.Tx,
	conversationID string,
	enabled bool,
	updatedAt time.Time,
) error {
	_, err := tx.ExecContext(
		ctx,
		`INSERT INTO zhizi_conversation_settings (conversation_id, enabled, updated_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT(conversation_id) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at`,
		conversationID,
		boolToInt(enabled),
		updatedAt.Unix(),
	)
	return err
}

func verifyZhiziConversationTx(
	ctx context.Context,
	tx *sql.Tx,
	conversationID string,
	ownerUserID string,
) error {
	var exists int
	err := tx.QueryRowContext(
		ctx,
		`SELECT 1 FROM conversations WHERE id = ? AND owner_user_id = ?`,
		conversationID,
		ownerUserID,
	).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrZhiziConversationUnauthorized
	}
	return err
}

func (db *DB) encryptZhiziSecret(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	return db.encryptJobSteps(value)
}

func (db *DB) decryptZhiziSecret(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	return db.decryptJobSteps(value)
}

func scanZhiziNode(scanner rowScanner) (ZhiziNode, error) {
	var item ZhiziNode
	var enabled int
	var lastTestAt, initStartedAt, initFinishedAt, createdAt, updatedAt int64
	err := scanner.Scan(
		&item.ID,
		&item.CreatedByUserID,
		&item.Name,
		&item.Host,
		&item.Port,
		&item.Username,
		&item.AuthType,
		&item.HostKeyFingerprint,
		&item.WorkRoot,
		&item.MaxSlots,
		&enabled,
		&lastTestAt,
		&item.LastTestError,
		&item.InitStatus,
		&item.InitMessage,
		&initStartedAt,
		&initFinishedAt,
		&createdAt,
		&updatedAt,
		&item.ActiveSlots,
	)
	if err != nil {
		return item, err
	}
	item.Enabled = enabled != 0
	item.LastTestAt = time.Unix(lastTestAt, 0)
	if initStartedAt > 0 {
		item.InitStartedAt = time.Unix(initStartedAt, 0)
	}
	if initFinishedAt > 0 {
		item.InitFinishedAt = time.Unix(initFinishedAt, 0)
	}
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	return item, nil
}

func scanZhiziLease(scanner rowScanner) (ZhiziLease, error) {
	var lease ZhiziLease
	var expiresAt, createdAt, updatedAt int64
	var node ZhiziNode
	var enabled int
	var nodeLastTestAt, nodeInitStartedAt, nodeInitFinishedAt, nodeCreatedAt, nodeUpdatedAt int64
	err := scanner.Scan(
		&lease.ID,
		&lease.NodeID,
		&lease.OwnerUserID,
		&lease.ConversationID,
		&lease.Status,
		&expiresAt,
		&createdAt,
		&updatedAt,
		&node.ID,
		&node.CreatedByUserID,
		&node.Name,
		&node.Host,
		&node.Port,
		&node.Username,
		&node.AuthType,
		&node.HostKeyFingerprint,
		&node.WorkRoot,
		&node.MaxSlots,
		&enabled,
		&nodeLastTestAt,
		&node.LastTestError,
		&node.InitStatus,
		&node.InitMessage,
		&nodeInitStartedAt,
		&nodeInitFinishedAt,
		&nodeCreatedAt,
		&nodeUpdatedAt,
		&node.ActiveSlots,
	)
	if err != nil {
		return lease, err
	}
	lease.ExpiresAt = time.Unix(expiresAt, 0)
	lease.CreatedAt = time.Unix(createdAt, 0)
	lease.UpdatedAt = time.Unix(updatedAt, 0)
	node.Enabled = enabled != 0
	node.LastTestAt = time.Unix(nodeLastTestAt, 0)
	if nodeInitStartedAt > 0 {
		node.InitStartedAt = time.Unix(nodeInitStartedAt, 0)
	}
	if nodeInitFinishedAt > 0 {
		node.InitFinishedAt = time.Unix(nodeInitFinishedAt, 0)
	}
	node.CreatedAt = time.Unix(nodeCreatedAt, 0)
	node.UpdatedAt = time.Unix(nodeUpdatedAt, 0)
	lease.Node = node
	return lease, nil
}

func truncateDatabaseText(value string, limit int) string {
	runes := []rune(strings.TrimSpace(value))
	if limit <= 0 || len(runes) <= limit {
		return string(runes)
	}
	return string(runes[:limit])
}
