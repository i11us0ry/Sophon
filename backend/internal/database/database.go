package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	*sql.DB
	jobKey []byte
}

type User struct {
	ID           string
	Username     string
	DisplayName  string
	PasswordHash string
	Role         string
	Enabled      bool
	CreatedAt    time.Time
}

type Session struct {
	ID         string
	UserID     string
	TokenHash  string
	CSRFHash   string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	LastSeenAt time.Time
}

func Open(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			log.Printf("database: 收紧数据目录权限失败 %s: %v", dir, err)
		}
	}

	// BEGIN IMMEDIATE serializes write transactions; WAL allows reads to run
	// concurrently on the remaining pooled connections.
	dsn := path + "?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on" +
		"&_txlock=immediate&_synchronous=NORMAL"
	sqlDB, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	sqlDB.SetMaxOpenConns(4)
	sqlDB.SetMaxIdleConns(4)

	jobKey, err := loadOrCreateJobKey(filepath.Join(filepath.Dir(path), ".sophon-job-key"))
	if err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	db := &DB{DB: sqlDB, jobKey: jobKey}
	if err := db.migrate(context.Background()); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	restrictDatabaseFilePermissions(path)
	return db, nil
}

// restrictDatabaseFilePermissions 把数据库及其 WAL/SHM 文件权限收紧为 0600（best-effort）。
func restrictDatabaseFilePermissions(path string) {
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(candidate, 0o600); err != nil && !os.IsNotExist(err) {
			log.Printf("database: 收紧文件权限失败 %s: %v", candidate, err)
		}
	}
}

func (db *DB) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			display_name TEXT NOT NULL DEFAULT '',
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'viewer',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS user_profiles (
			user_id TEXT PRIMARY KEY,
			assistant_name TEXT NOT NULL DEFAULT 'Sophon',
			assistant_avatar TEXT NOT NULL DEFAULT '',
			user_avatar TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL DEFAULT 0,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			csrf_hash TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			last_seen_at INTEGER NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,
		`CREATE TABLE IF NOT EXISTS conversations (
			id TEXT PRIMARY KEY,
			owner_user_id TEXT NOT NULL,
			project_id TEXT NOT NULL DEFAULT '',
			asset_id TEXT NOT NULL DEFAULT '',
			kind TEXT NOT NULL DEFAULT 'normal',
			parent_conversation_id TEXT NOT NULL DEFAULT '',
			batch_id TEXT NOT NULL DEFAULT '',
			title TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_conversations_owner_updated
		 ON conversations(owner_user_id, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS zhizi_nodes (
				id TEXT PRIMARY KEY,
				created_by_user_id TEXT NOT NULL,
				name TEXT NOT NULL COLLATE NOCASE UNIQUE,
				host TEXT NOT NULL,
				port INTEGER NOT NULL DEFAULT 22,
				username TEXT NOT NULL,
				auth_type TEXT NOT NULL DEFAULT 'key',
				password_cipher TEXT NOT NULL DEFAULT '',
				private_key_cipher TEXT NOT NULL DEFAULT '',
				host_key_fingerprint TEXT NOT NULL DEFAULT '',
				work_root TEXT NOT NULL DEFAULT '/home/sophon/sophon',
				max_slots INTEGER NOT NULL DEFAULT 1,
				enabled INTEGER NOT NULL DEFAULT 1,
				last_test_at INTEGER NOT NULL DEFAULT 0,
				last_test_error TEXT NOT NULL DEFAULT '',
				init_status TEXT NOT NULL DEFAULT 'never',
				init_message TEXT NOT NULL DEFAULT '',
				init_started_at INTEGER NOT NULL DEFAULT 0,
				init_finished_at INTEGER NOT NULL DEFAULT 0,
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL
			)`,
		`CREATE TABLE IF NOT EXISTS zhizi_conversation_settings (
				conversation_id TEXT PRIMARY KEY,
				enabled INTEGER NOT NULL DEFAULT 0,
				updated_at INTEGER NOT NULL,
				FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
			)`,
		`CREATE TABLE IF NOT EXISTS zhizi_leases (
				id TEXT PRIMARY KEY,
				node_id TEXT NOT NULL,
				owner_user_id TEXT NOT NULL,
				conversation_id TEXT NOT NULL,
				status TEXT NOT NULL DEFAULT 'active',
				expires_at INTEGER NOT NULL,
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL,
				FOREIGN KEY (node_id) REFERENCES zhizi_nodes(id),
				FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
			)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_zhizi_leases_active_conversation
			 ON zhizi_leases(conversation_id) WHERE status = 'active'`,
		`CREATE INDEX IF NOT EXISTS idx_zhizi_leases_node_status
			 ON zhizi_leases(node_id, status, expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_zhizi_leases_owner_status
			 ON zhizi_leases(owner_user_id, status, expires_at)`,
		`CREATE TABLE IF NOT EXISTS conversation_batches (
			id TEXT PRIMARY KEY,
			owner_user_id TEXT NOT NULL,
			project_id TEXT NOT NULL,
			parent_conversation_id TEXT NOT NULL,
			title TEXT NOT NULL,
			instruction TEXT NOT NULL DEFAULT '',
			source_text TEXT NOT NULL DEFAULT '',
			total INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'draft',
			max_concurrency INTEGER NOT NULL DEFAULT 3,
			max_attempts_per_task INTEGER NOT NULL DEFAULT 2,
			max_segments_per_task INTEGER NOT NULL DEFAULT 6,
			max_tool_calls_per_task INTEGER NOT NULL DEFAULT 60,
			campaign_mode TEXT NOT NULL DEFAULT 'single',
			resume_on_start INTEGER NOT NULL DEFAULT 0,
			campaign_round INTEGER NOT NULL DEFAULT 0,
			max_rounds INTEGER NOT NULL DEFAULT 3,
			campaign_tool_call_budget INTEGER NOT NULL DEFAULT 600,
			campaign_tool_calls INTEGER NOT NULL DEFAULT 0,
			stopped_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			started_at INTEGER NOT NULL DEFAULT 0,
			finished_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_conversation_batches_owner
		 ON conversation_batches(owner_user_id, updated_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_conversation_batches_project
		 ON conversation_batches(project_id, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS campaign_groups (
			id TEXT PRIMARY KEY,
			campaign_id TEXT NOT NULL,
			project_id TEXT NOT NULL,
			owner_user_id TEXT NOT NULL,
			group_key TEXT NOT NULL,
			label TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'queued',
			total_assets INTEGER NOT NULL DEFAULT 0,
			completed_assets INTEGER NOT NULL DEFAULT 0,
			failed_assets INTEGER NOT NULL DEFAULT 0,
			business_system TEXT NOT NULL DEFAULT '',
			business_priority INTEGER NOT NULL DEFAULT 50,
			priority_score INTEGER NOT NULL DEFAULT 50,
			priority_reason TEXT NOT NULL DEFAULT '',
			priority_updated_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_campaign_groups_key
		 ON campaign_groups(campaign_id, group_key)`,
		`CREATE TABLE IF NOT EXISTS campaign_endpoints (
			id TEXT PRIMARY KEY,
			campaign_id TEXT NOT NULL,
			group_id TEXT NOT NULL,
			asset_id TEXT NOT NULL,
			project_id TEXT NOT NULL,
			owner_user_id TEXT NOT NULL,
			method TEXT NOT NULL DEFAULT 'GET',
			url TEXT NOT NULL,
			host TEXT NOT NULL DEFAULT '',
			path TEXT NOT NULL DEFAULT '',
			fingerprint TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'queued',
			risk_score INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_campaign_endpoints_fingerprint
		 ON campaign_endpoints(campaign_id, fingerprint)`,
		`CREATE INDEX IF NOT EXISTS idx_campaign_endpoints_asset
		 ON campaign_endpoints(campaign_id, asset_id, status)`,
		`CREATE TABLE IF NOT EXISTS campaign_tasks (
			id TEXT PRIMARY KEY,
			campaign_id TEXT NOT NULL,
			group_id TEXT NOT NULL,
			asset_id TEXT NOT NULL,
			conversation_id TEXT NOT NULL,
			project_id TEXT NOT NULL,
			owner_user_id TEXT NOT NULL,
			kind TEXT NOT NULL DEFAULT 'asset_scan',
			parent_task_id TEXT NOT NULL DEFAULT '',
			source_type TEXT NOT NULL DEFAULT '',
			source_ref TEXT NOT NULL DEFAULT '',
			intent_json TEXT NOT NULL DEFAULT '{}',
			status TEXT NOT NULL DEFAULT 'queued',
			priority INTEGER NOT NULL DEFAULT 50,
			attempts INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 2,
			max_segments INTEGER NOT NULL DEFAULT 6,
			max_tool_calls INTEGER NOT NULL DEFAULT 60,
			tool_calls INTEGER NOT NULL DEFAULT 0,
			result TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			next_attempt_at INTEGER NOT NULL DEFAULT 0,
			failure_kind TEXT NOT NULL DEFAULT '',
			started_at INTEGER NOT NULL DEFAULT 0,
			finished_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`DROP INDEX IF EXISTS idx_campaign_tasks_asset_kind`,
		`CREATE INDEX IF NOT EXISTS idx_campaign_tasks_schedule
		 ON campaign_tasks(campaign_id, status, priority DESC, created_at ASC)`,
		`CREATE INDEX IF NOT EXISTS idx_campaign_tasks_owner_status_conversation
		 ON campaign_tasks(owner_user_id, status, conversation_id)`,
		`CREATE TABLE IF NOT EXISTS campaign_frontier (
			id TEXT PRIMARY KEY,
			campaign_id TEXT NOT NULL,
			group_id TEXT NOT NULL DEFAULT '',
			asset_id TEXT NOT NULL DEFAULT '',
			task_id TEXT NOT NULL DEFAULT '',
			kind TEXT NOT NULL,
			priority INTEGER NOT NULL DEFAULT 50,
			reason TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending',
			dedupe_key TEXT NOT NULL,
			source_type TEXT NOT NULL DEFAULT '',
			source_ref TEXT NOT NULL DEFAULT '',
			intent_json TEXT NOT NULL DEFAULT '{}',
			expected_value INTEGER NOT NULL DEFAULT 50,
			estimated_cost INTEGER NOT NULL DEFAULT 1,
			roi INTEGER NOT NULL DEFAULT 50,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_campaign_frontier_dedupe
		 ON campaign_frontier(campaign_id, dedupe_key)`,
		`CREATE INDEX IF NOT EXISTS idx_campaign_frontier_priority
		 ON campaign_frontier(campaign_id, status, priority DESC, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS campaign_links (
			id TEXT PRIMARY KEY,
			campaign_id TEXT NOT NULL,
			project_id TEXT NOT NULL,
			src_asset_id TEXT NOT NULL,
			dst_asset_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			summary TEXT NOT NULL DEFAULT '',
			confidence INTEGER NOT NULL DEFAULT 0,
			src_fact_id TEXT NOT NULL DEFAULT '',
			src_finding_id TEXT NOT NULL DEFAULT '',
			evidence_refs TEXT NOT NULL DEFAULT '[]',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_campaign_links_unique
		 ON campaign_links(campaign_id, src_asset_id, dst_asset_id, kind, src_fact_id, src_finding_id)`,
		`CREATE INDEX IF NOT EXISTS idx_campaign_links_asset
		 ON campaign_links(campaign_id, src_asset_id, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS campaign_verifications (
			id TEXT PRIMARY KEY,
			campaign_id TEXT NOT NULL,
			finding_id TEXT NOT NULL,
			task_id TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending',
			attempts INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 2,
			result TEXT NOT NULL DEFAULT '',
			evidence_refs TEXT NOT NULL DEFAULT '[]',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_campaign_verifications_finding
		 ON campaign_verifications(campaign_id, finding_id)`,
		`CREATE INDEX IF NOT EXISTS idx_campaign_verifications_status
		 ON campaign_verifications(campaign_id, status, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS campaign_coverage (
			campaign_id TEXT NOT NULL,
			asset_id TEXT NOT NULL,
			dimension TEXT NOT NULL,
			technique TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'untested',
			attempts INTEGER NOT NULL DEFAULT 0,
			evidence_refs TEXT NOT NULL DEFAULT '[]',
			updated_at INTEGER NOT NULL,
			PRIMARY KEY(campaign_id, asset_id, dimension, technique)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_campaign_coverage_status
		 ON campaign_coverage(campaign_id, status, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS campaign_chains (
			id TEXT PRIMARY KEY,
			campaign_id TEXT NOT NULL,
			project_id TEXT NOT NULL,
			fingerprint TEXT NOT NULL,
			title TEXT NOT NULL,
			kind TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'candidate',
			priority INTEGER NOT NULL DEFAULT 50,
			confidence INTEGER NOT NULL DEFAULT 60,
			entry_asset_id TEXT NOT NULL DEFAULT '',
			target_asset_id TEXT NOT NULL DEFAULT '',
			src_finding_id TEXT NOT NULL DEFAULT '',
			src_fact_id TEXT NOT NULL DEFAULT '',
			evidence_refs TEXT NOT NULL DEFAULT '[]',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_campaign_chains_fingerprint
		 ON campaign_chains(campaign_id, fingerprint)`,
		`CREATE INDEX IF NOT EXISTS idx_campaign_chains_priority
		 ON campaign_chains(campaign_id, status, priority DESC, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS campaign_chain_steps (
			id TEXT PRIMARY KEY,
			chain_id TEXT NOT NULL,
			step_order INTEGER NOT NULL DEFAULT 0,
			kind TEXT NOT NULL DEFAULT '',
			asset_id TEXT NOT NULL DEFAULT '',
			source_ref TEXT NOT NULL DEFAULT '',
			summary TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_campaign_chain_steps_chain
		 ON campaign_chain_steps(chain_id, step_order)`,
		`CREATE TABLE IF NOT EXISTS campaign_memory_digests (
			id TEXT PRIMARY KEY,
			campaign_id TEXT NOT NULL,
			project_id TEXT NOT NULL,
			scope_type TEXT NOT NULL DEFAULT 'campaign',
			scope_id TEXT NOT NULL DEFAULT '',
			tier TEXT NOT NULL DEFAULT 'hot',
			kind TEXT NOT NULL DEFAULT 'summary',
			summary TEXT NOT NULL DEFAULT '',
			payload_json TEXT NOT NULL DEFAULT '{}',
			source_count INTEGER NOT NULL DEFAULT 0,
			freshness INTEGER NOT NULL DEFAULT 0,
			expires_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_campaign_memory_scope
		 ON campaign_memory_digests(campaign_id, scope_type, scope_id, kind)`,
		`CREATE INDEX IF NOT EXISTS idx_campaign_memory_tier
		 ON campaign_memory_digests(campaign_id, tier, freshness DESC, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS agent_runs (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			assistant_message_id TEXT NOT NULL DEFAULT '',
			resume_of TEXT NOT NULL DEFAULT '',
			agent_mode TEXT NOT NULL DEFAULT 'deep',
			status TEXT NOT NULL,
			segment_count INTEGER NOT NULL DEFAULT 0,
			progress_json TEXT NOT NULL DEFAULT '{}',
			interruption_reason TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			started_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			finished_at INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_runs_conversation
		 ON agent_runs(conversation_id, started_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_runs_status
		 ON agent_runs(status, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS messages (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			role TEXT NOT NULL,
			content TEXT NOT NULL,
			reasoning_content TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_messages_conversation_created
		 ON messages(conversation_id, created_at)`,
		`CREATE TABLE IF NOT EXISTS process_details (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			message_id TEXT,
			event_type TEXT NOT NULL,
			message TEXT NOT NULL DEFAULT '',
			data TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_process_details_conversation_created
		 ON process_details(conversation_id, created_at)`,
		`CREATE TABLE IF NOT EXISTS attachments (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			message_id TEXT REFERENCES messages(id) ON DELETE CASCADE,
			file_name TEXT NOT NULL,
			mime_type TEXT NOT NULL DEFAULT '',
			size_bytes INTEGER NOT NULL DEFAULT 0,
			storage_path TEXT NOT NULL,
			text_content TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_attachments_conversation_created
		 ON attachments(conversation_id, created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_attachments_message
		 ON attachments(message_id)`,
		`CREATE TABLE IF NOT EXISTS conversation_summaries (
			conversation_id TEXT PRIMARY KEY,
			summary TEXT NOT NULL DEFAULT '',
			through_message_id TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS context_compactions (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			tokens_before INTEGER NOT NULL DEFAULT 0,
			tokens_after INTEGER NOT NULL DEFAULT 0,
			summary_tokens INTEGER NOT NULL DEFAULT 0,
			model TEXT NOT NULL DEFAULT '',
			latency_ms INTEGER NOT NULL DEFAULT 0,
			trigger_ratio REAL NOT NULL DEFAULT 0,
			transcript_path TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_context_compactions_conversation
		 ON context_compactions(conversation_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS tool_executions (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL DEFAULT '',
			user_id TEXT NOT NULL DEFAULT '',
			tool_name TEXT NOT NULL,
			arguments TEXT NOT NULL DEFAULT '{}',
			fingerprint TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			result TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			started_at INTEGER NOT NULL,
			finished_at INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tool_executions_conversation_started
		 ON tool_executions(conversation_id, started_at DESC)`,
		`CREATE TABLE IF NOT EXISTS tool_jobs (
				id TEXT PRIMARY KEY,
				conversation_id TEXT NOT NULL,
				user_id TEXT NOT NULL,
				agent_id TEXT NOT NULL DEFAULT '',
				dedup_key TEXT NOT NULL,
				status TEXT NOT NULL,
				steps_json TEXT NOT NULL DEFAULT '[]',
				next_step INTEGER NOT NULL DEFAULT 0,
				progress_json TEXT NOT NULL DEFAULT '{}',
				result TEXT NOT NULL DEFAULT '',
				error TEXT NOT NULL DEFAULT '',
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL,
				finished_at INTEGER
			)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_tool_jobs_dedupe
			 ON tool_jobs(conversation_id, user_id, dedup_key)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_tool_jobs_one_running_per_agent
			 ON tool_jobs(conversation_id, user_id, agent_id)
			 WHERE status = 'running'`,
		`CREATE INDEX IF NOT EXISTS idx_tool_jobs_conversation_status
			 ON tool_jobs(conversation_id, status, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL DEFAULT '',
			username TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL,
			resource_type TEXT NOT NULL DEFAULT '',
			resource_id TEXT NOT NULL DEFAULT '',
			result TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at
		 ON audit_logs(created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS hitl_requests (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			tool_name TEXT NOT NULL,
			arguments TEXT NOT NULL DEFAULT '{}',
			status TEXT NOT NULL,
			comment TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			decided_at INTEGER,
			decided_by TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_hitl_requests_status_created
		 ON hitl_requests(status, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS conversation_hitl_settings (
			conversation_id TEXT PRIMARY KEY,
			enabled INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS conversation_agent_settings (
			conversation_id TEXT PRIMARY KEY,
			auto_continue INTEGER NOT NULL DEFAULT 1,
			asset_restriction_enabled INTEGER NOT NULL DEFAULT 1,
			updated_at INTEGER NOT NULL,
			FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS projects (
			id TEXT PRIMARY KEY,
			owner_user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			goals TEXT NOT NULL DEFAULT '',
			scope TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'active',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS project_facts (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			asset_id TEXT NOT NULL DEFAULT '',
			fact_type TEXT NOT NULL,
			key TEXT NOT NULL,
			value TEXT NOT NULL,
			summary TEXT NOT NULL DEFAULT '',
			body TEXT NOT NULL DEFAULT '',
				evidence TEXT NOT NULL DEFAULT '',
				relation TEXT NOT NULL DEFAULT '',
				confidence INTEGER NOT NULL DEFAULT 100,
				memory_kind TEXT NOT NULL DEFAULT 'general',
				priority INTEGER NOT NULL DEFAULT 50,
				pinned INTEGER NOT NULL DEFAULT 0,
				observed_at INTEGER NOT NULL DEFAULT 0,
				contradicted_by TEXT NOT NULL DEFAULT '',
				conflict_reason TEXT NOT NULL DEFAULT '',
				subject_type TEXT NOT NULL DEFAULT '',
				subject_key TEXT NOT NULL DEFAULT '',
				predicate TEXT NOT NULL DEFAULT '',
				object_type TEXT NOT NULL DEFAULT '',
				object_key TEXT NOT NULL DEFAULT '',
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL,
				FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
			)`,
		`CREATE INDEX IF NOT EXISTS idx_project_facts_project
		 ON project_facts(project_id, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS project_memory_entities (
				id TEXT PRIMARY KEY,
				project_id TEXT NOT NULL,
				entity_type TEXT NOT NULL,
				entity_key TEXT NOT NULL,
				label TEXT NOT NULL DEFAULT '',
				summary TEXT NOT NULL DEFAULT '',
				metadata TEXT NOT NULL DEFAULT '{}',
				source_ref_id TEXT NOT NULL DEFAULT '',
				evidence TEXT NOT NULL DEFAULT '',
				evidence_refs TEXT NOT NULL DEFAULT '[]',
				confidence INTEGER NOT NULL DEFAULT 0,
				priority INTEGER NOT NULL DEFAULT 50,
				valid_from INTEGER NOT NULL DEFAULT 0,
				valid_to INTEGER NOT NULL DEFAULT 0,
				superseded_by TEXT NOT NULL DEFAULT '',
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL,
				FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
			)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_project_memory_entities_unique
			 ON project_memory_entities(project_id, entity_type, entity_key)`,
		`CREATE INDEX IF NOT EXISTS idx_project_memory_entities_project
			 ON project_memory_entities(project_id, entity_type, priority DESC, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS project_memory_relations (
				id TEXT PRIMARY KEY,
				project_id TEXT NOT NULL,
				src_entity_id TEXT NOT NULL,
				relation TEXT NOT NULL,
				dst_entity_id TEXT NOT NULL,
				fact_id TEXT NOT NULL DEFAULT '',
				confidence INTEGER NOT NULL DEFAULT 0,
				evidence TEXT NOT NULL DEFAULT '',
				evidence_refs TEXT NOT NULL DEFAULT '[]',
				valid_from INTEGER NOT NULL DEFAULT 0,
				valid_to INTEGER NOT NULL DEFAULT 0,
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL,
				FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
			)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_project_memory_relations_unique
			 ON project_memory_relations(project_id, src_entity_id, relation, dst_entity_id)`,
		`CREATE INDEX IF NOT EXISTS idx_project_memory_relations_src
			 ON project_memory_relations(project_id, src_entity_id, relation)`,
		`CREATE INDEX IF NOT EXISTS idx_project_memory_relations_dst
			 ON project_memory_relations(project_id, dst_entity_id, relation)`,
		`CREATE TABLE IF NOT EXISTS project_fact_versions (
				id TEXT PRIMARY KEY,
				project_id TEXT NOT NULL,
				fact_id TEXT NOT NULL,
				version INTEGER NOT NULL DEFAULT 1,
				summary TEXT NOT NULL DEFAULT '',
				body TEXT NOT NULL DEFAULT '',
				evidence TEXT NOT NULL DEFAULT '',
				relation TEXT NOT NULL DEFAULT '',
				confidence INTEGER NOT NULL DEFAULT 0,
				memory_kind TEXT NOT NULL DEFAULT 'general',
				priority INTEGER NOT NULL DEFAULT 50,
				source_type TEXT NOT NULL DEFAULT '',
				source_id TEXT NOT NULL DEFAULT '',
				reason TEXT NOT NULL DEFAULT '',
				created_at INTEGER NOT NULL,
				FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
			)`,
		`CREATE INDEX IF NOT EXISTS idx_project_fact_versions_fact
			 ON project_fact_versions(project_id, fact_id, version DESC)`,
		`CREATE TABLE IF NOT EXISTS memory_writes (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			fact_id TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			before_summary TEXT NOT NULL DEFAULT '',
			after_summary TEXT NOT NULL DEFAULT '',
			source_type TEXT NOT NULL DEFAULT '',
			source_id TEXT NOT NULL DEFAULT '',
			similarity REAL NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_memory_writes_project
		 ON memory_writes(project_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS injection_events (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL DEFAULT '',
			project_id TEXT NOT NULL DEFAULT '',
			source_type TEXT NOT NULL DEFAULT '',
			source_id TEXT NOT NULL DEFAULT '',
			patterns TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_injection_events_conversation
		 ON injection_events(conversation_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS assets (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL DEFAULT '',
			owner_user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			kind TEXT NOT NULL,
			value TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'unknown',
			criticality TEXT NOT NULL DEFAULT 'medium',
			risk_score INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_assets_owner
		 ON assets(owner_user_id, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS vulnerabilities (
				id TEXT PRIMARY KEY,
				project_id TEXT NOT NULL DEFAULT '',
				asset_id TEXT NOT NULL DEFAULT '',
				owner_user_id TEXT NOT NULL,
			title TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'medium',
			status TEXT NOT NULL DEFAULT 'open',
			description TEXT NOT NULL DEFAULT '',
			evidence TEXT NOT NULL DEFAULT '',
			vulnerability_type TEXT NOT NULL DEFAULT '',
			target TEXT NOT NULL DEFAULT '',
			parameter TEXT NOT NULL DEFAULT '',
			http_method TEXT NOT NULL DEFAULT '',
			preconditions TEXT NOT NULL DEFAULT '',
			reproduction_steps TEXT NOT NULL DEFAULT '',
				evidence_refs TEXT NOT NULL DEFAULT '[]',
				impact TEXT NOT NULL DEFAULT '',
				recommendation TEXT NOT NULL DEFAULT '',
				retest_notes TEXT NOT NULL DEFAULT '',
				fingerprint TEXT NOT NULL DEFAULT '',
				verification_state TEXT NOT NULL DEFAULT 'unverified',
				confidence INTEGER NOT NULL DEFAULT 0,
				exploitability TEXT NOT NULL DEFAULT '',
				test_technique TEXT NOT NULL DEFAULT '',
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL
			)`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_owner
			 ON vulnerabilities(owner_user_id, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS vulnerability_retests (
			id TEXT PRIMARY KEY,
			vulnerability_id TEXT NOT NULL,
			owner_user_id TEXT NOT NULL,
			result TEXT NOT NULL,
			status_before TEXT NOT NULL,
			status_after TEXT NOT NULL,
			notes TEXT NOT NULL DEFAULT '',
			evidence TEXT NOT NULL DEFAULT '',
			evidence_refs TEXT NOT NULL DEFAULT '[]',
			status TEXT NOT NULL DEFAULT 'completed',
			conversation_id TEXT NOT NULL DEFAULT '',
			task_id TEXT NOT NULL DEFAULT '',
			source_conversation_ids TEXT NOT NULL DEFAULT '[]',
			started_at INTEGER NOT NULL DEFAULT 0,
			completed_at INTEGER NOT NULL DEFAULT 0,
			error TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerability_retests_vulnerability
		 ON vulnerability_retests(vulnerability_id, owner_user_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS knowledge_items (
			id TEXT PRIMARY KEY,
			owner_user_id TEXT NOT NULL,
			category TEXT NOT NULL DEFAULT 'general',
			title TEXT NOT NULL,
			content TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_knowledge_items_owner
		 ON knowledge_items(owner_user_id, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS knowledge_chunks (
			id TEXT PRIMARY KEY,
			item_id TEXT NOT NULL,
			chunk_index INTEGER NOT NULL,
			content TEXT NOT NULL,
			embedding TEXT NOT NULL,
			updated_at INTEGER NOT NULL,
			FOREIGN KEY (item_id) REFERENCES knowledge_items(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_item
		 ON knowledge_chunks(item_id, chunk_index)`,
		`CREATE TABLE IF NOT EXISTS webshell_connections (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL DEFAULT '',
			owner_user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			url TEXT NOT NULL,
			method TEXT NOT NULL DEFAULT 'POST',
			password TEXT NOT NULL DEFAULT '',
			encoding TEXT NOT NULL DEFAULT 'utf-8',
			status TEXT NOT NULL DEFAULT 'unknown',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webshell_connections_owner
		 ON webshell_connections(owner_user_id, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS rbac_roles (
			name TEXT PRIMARY KEY,
			description TEXT NOT NULL DEFAULT '',
			permissions_json TEXT NOT NULL DEFAULT '[]',
			builtin INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS token_usage (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL DEFAULT '',
				project_id TEXT NOT NULL DEFAULT '',
			user_id TEXT NOT NULL,
			message_id TEXT NOT NULL DEFAULT '',
			prompt_tokens INTEGER NOT NULL DEFAULT 0,
			cache_read_tokens INTEGER NOT NULL DEFAULT 0,
			completion_tokens INTEGER NOT NULL DEFAULT 0,
			total_tokens INTEGER NOT NULL DEFAULT 0,
			estimated INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_token_usage_user_created
		 ON token_usage(user_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS agent_roles (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			prompt TEXT NOT NULL DEFAULT '',
			icon TEXT NOT NULL DEFAULT '',
			default_mode TEXT NOT NULL DEFAULT 'auto',
			skills_json TEXT NOT NULL DEFAULT '[]',
			builtin INTEGER NOT NULL DEFAULT 0,
			enabled INTEGER NOT NULL DEFAULT 1,
			deleted INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_roles_enabled
		 ON agent_roles(enabled, name)`,
		`CREATE TABLE IF NOT EXISTS mcp_servers (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			transport TEXT NOT NULL DEFAULT 'stdio',
			command TEXT NOT NULL DEFAULT '',
			args_json TEXT NOT NULL DEFAULT '[]',
			env_json TEXT NOT NULL DEFAULT '{}',
			url TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'unknown',
			last_error TEXT NOT NULL DEFAULT '',
			tool_count INTEGER NOT NULL DEFAULT 0,
			builtin INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS mcp_tool_settings (
			server_name TEXT NOT NULL,
			tool_name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			capability TEXT NOT NULL DEFAULT 'destructive',
			updated_at INTEGER NOT NULL,
			PRIMARY KEY (server_name, tool_name)
		)`,
		`CREATE TABLE IF NOT EXISTS intercept_rules (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			priority INTEGER NOT NULL DEFAULT 50,
			match_target TEXT NOT NULL DEFAULT 'tool_input',
			match_type TEXT NOT NULL DEFAULT 'regex',
			pattern TEXT NOT NULL,
			action TEXT NOT NULL DEFAULT 'ask',
			message TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_intercept_rules_priority
		 ON intercept_rules(enabled, priority DESC, created_at ASC)`,
		`CREATE TABLE IF NOT EXISTS project_attack_steps (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			step_order INTEGER NOT NULL DEFAULT 0,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'todo',
			severity TEXT NOT NULL DEFAULT 'medium',
			technique TEXT NOT NULL DEFAULT '',
			evidence TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_project_attack_steps_project
		 ON project_attack_steps(project_id, step_order)`,
		`CREATE TABLE IF NOT EXISTS project_graph_nodes (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			title TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT '',
			confidence INTEGER NOT NULL DEFAULT 0,
			severity TEXT NOT NULL DEFAULT '',
			asset_id TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL DEFAULT 'manual',
			source_ref_id TEXT NOT NULL DEFAULT '',
			pos_x INTEGER NOT NULL DEFAULT 0,
			pos_y INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_project_graph_nodes_project
		 ON project_graph_nodes(project_id, kind, updated_at DESC)`,
		`CREATE TABLE IF NOT EXISTS project_graph_edges (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			src_id TEXT NOT NULL,
			dst_id TEXT NOT NULL,
			rel TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_project_graph_edges_project
			 ON project_graph_edges(project_id)`,
		`CREATE TABLE IF NOT EXISTS project_test_results (
				id TEXT PRIMARY KEY,
				project_id TEXT NOT NULL,
				asset_id TEXT NOT NULL DEFAULT '',
				dimension TEXT NOT NULL,
				technique TEXT NOT NULL DEFAULT '',
				status TEXT NOT NULL DEFAULT 'untested',
				result TEXT NOT NULL DEFAULT '',
				evidence TEXT NOT NULL DEFAULT '',
				evidence_refs TEXT NOT NULL DEFAULT '[]',
				confidence INTEGER NOT NULL DEFAULT 0,
				finding_id TEXT NOT NULL DEFAULT '',
				intent_id TEXT NOT NULL DEFAULT '',
				rationale TEXT NOT NULL DEFAULT '',
				expected_evidence TEXT NOT NULL DEFAULT '',
				priority INTEGER NOT NULL DEFAULT 0,
				parent_finding_id TEXT NOT NULL DEFAULT '',
				attempts INTEGER NOT NULL DEFAULT 0,
				required INTEGER NOT NULL DEFAULT 1,
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL,
				FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
			)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_project_test_results_unique
			 ON project_test_results(project_id, asset_id, dimension, technique)`,
		`CREATE INDEX IF NOT EXISTS idx_project_test_results_project
			 ON project_test_results(project_id, status, updated_at DESC)`,
	}

	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("database migration: %w", err)
		}
	}
	for _, cleanup := range []string{
		`DROP TABLE IF EXISTS intent_drafts`,
		`DELETE FROM agent_roles WHERE id = 'system-intent-router'`,
	} {
		if _, err := db.ExecContext(ctx, cleanup); err != nil {
			return fmt.Errorf("database cleanup: %w", err)
		}
	}
	if err := db.ensureColumn(
		ctx,
		"conversation_agent_settings",
		"asset_restriction_enabled",
		`ALTER TABLE conversation_agent_settings
		 ADD COLUMN asset_restriction_enabled INTEGER NOT NULL DEFAULT 1`,
	); err != nil {
		return err
	}
	if err := db.ensureColumn(
		ctx,
		"zhizi_nodes",
		"host_key_fingerprint",
		`ALTER TABLE zhizi_nodes ADD COLUMN host_key_fingerprint TEXT NOT NULL DEFAULT ''`,
	); err != nil {
		return err
	}
	if err := db.dropColumnIfExists(ctx, "zhizi_nodes", "known_hosts"); err != nil {
		return err
	}
	for _, column := range []struct {
		name string
		sql  string
	}{
		{"init_status", `ALTER TABLE zhizi_nodes ADD COLUMN init_status TEXT NOT NULL DEFAULT 'never'`},
		{"init_message", `ALTER TABLE zhizi_nodes ADD COLUMN init_message TEXT NOT NULL DEFAULT ''`},
		{"init_started_at", `ALTER TABLE zhizi_nodes ADD COLUMN init_started_at INTEGER NOT NULL DEFAULT 0`},
		{"init_finished_at", `ALTER TABLE zhizi_nodes ADD COLUMN init_finished_at INTEGER NOT NULL DEFAULT 0`},
	} {
		if err := db.ensureColumn(ctx, "zhizi_nodes", column.name, column.sql); err != nil {
			return err
		}
	}
	if err := db.encryptLegacyToolJobSteps(ctx); err != nil {
		return fmt.Errorf("encrypt legacy tool job steps: %w", err)
	}
	if err := db.ensureColumn(
		ctx,
		"agent_runs",
		"agent_mode",
		`ALTER TABLE agent_runs ADD COLUMN agent_mode TEXT NOT NULL DEFAULT 'deep'`,
	); err != nil {
		return err
	}
	if err := db.ensureColumn(
		ctx,
		"tool_executions",
		"fingerprint",
		`ALTER TABLE tool_executions ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''`,
	); err != nil {
		return err
	}
	if _, err := db.ExecContext(
		ctx,
		`CREATE INDEX IF NOT EXISTS idx_tool_executions_probe_fingerprint
		 ON tool_executions(conversation_id, tool_name, fingerprint, started_at DESC)`,
	); err != nil {
		return fmt.Errorf("create tool execution fingerprint index: %w", err)
	}
	// 全量导入 ARTEX 内置拦截规则（按名称幂等，不覆盖用户修改）。
	if err := db.seedDefaultInterceptRules(ctx); err != nil {
		return fmt.Errorf("seed intercept rules: %w", err)
	}
	if err := db.ensureColumn(
		ctx,
		"conversations",
		"project_id",
		`ALTER TABLE conversations ADD COLUMN project_id TEXT NOT NULL DEFAULT ''`,
	); err != nil {
		return err
	}
	if err := db.ensureColumn(
		ctx,
		"users",
		"display_name",
		`ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''`,
	); err != nil {
		return err
	}
	if err := db.ensureColumn(
		ctx,
		"conversations",
		"agent_role_id",
		`ALTER TABLE conversations ADD COLUMN agent_role_id TEXT NOT NULL DEFAULT ''`,
	); err != nil {
		return err
	}
	if err := db.ensureColumn(
		ctx,
		"agent_roles",
		"deleted",
		`ALTER TABLE agent_roles ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0`,
	); err != nil {
		return err
	}
	if err := db.ensureColumn(
		ctx,
		"agent_roles",
		"default_mode",
		`ALTER TABLE agent_roles ADD COLUMN default_mode TEXT NOT NULL DEFAULT 'auto'`,
	); err != nil {
		return err
	}
	if err := db.ensureColumn(
		ctx,
		"conversations",
		"asset_id",
		"ALTER TABLE conversations ADD COLUMN asset_id TEXT NOT NULL DEFAULT ''",
	); err != nil {
		return err
	}
	for column, statement := range map[string]string{
		"kind":                   "ALTER TABLE conversations ADD COLUMN kind TEXT NOT NULL DEFAULT 'normal'",
		"parent_conversation_id": "ALTER TABLE conversations ADD COLUMN parent_conversation_id TEXT NOT NULL DEFAULT ''",
		"batch_id":               "ALTER TABLE conversations ADD COLUMN batch_id TEXT NOT NULL DEFAULT ''",
	} {
		if err := db.ensureColumn(ctx, "conversations", column, statement); err != nil {
			return err
		}
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS idx_conversations_owner_parent
		 ON conversations(owner_user_id, parent_conversation_id, updated_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_conversations_batch
		 ON conversations(batch_id, updated_at DESC)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	campaignBatchColumns := map[string]string{
		"status":                    "ALTER TABLE conversation_batches ADD COLUMN status TEXT NOT NULL DEFAULT 'draft'",
		"max_concurrency":           "ALTER TABLE conversation_batches ADD COLUMN max_concurrency INTEGER NOT NULL DEFAULT 3",
		"max_attempts_per_task":     "ALTER TABLE conversation_batches ADD COLUMN max_attempts_per_task INTEGER NOT NULL DEFAULT 2",
		"max_segments_per_task":     "ALTER TABLE conversation_batches ADD COLUMN max_segments_per_task INTEGER NOT NULL DEFAULT 6",
		"max_tool_calls_per_task":   "ALTER TABLE conversation_batches ADD COLUMN max_tool_calls_per_task INTEGER NOT NULL DEFAULT 60",
		"campaign_mode":             "ALTER TABLE conversation_batches ADD COLUMN campaign_mode TEXT NOT NULL DEFAULT 'single'",
		"resume_on_start":           "ALTER TABLE conversation_batches ADD COLUMN resume_on_start INTEGER NOT NULL DEFAULT 0",
		"campaign_round":            "ALTER TABLE conversation_batches ADD COLUMN campaign_round INTEGER NOT NULL DEFAULT 0",
		"max_rounds":                "ALTER TABLE conversation_batches ADD COLUMN max_rounds INTEGER NOT NULL DEFAULT 3",
		"campaign_tool_call_budget": "ALTER TABLE conversation_batches ADD COLUMN campaign_tool_call_budget INTEGER NOT NULL DEFAULT 600",
		"campaign_tool_calls":       "ALTER TABLE conversation_batches ADD COLUMN campaign_tool_calls INTEGER NOT NULL DEFAULT 0",
		"stopped_at":                "ALTER TABLE conversation_batches ADD COLUMN stopped_at INTEGER NOT NULL DEFAULT 0",
		"started_at":                "ALTER TABLE conversation_batches ADD COLUMN started_at INTEGER NOT NULL DEFAULT 0",
		"finished_at":               "ALTER TABLE conversation_batches ADD COLUMN finished_at INTEGER NOT NULL DEFAULT 0",
	}
	for column, statement := range campaignBatchColumns {
		if err := db.ensureColumn(ctx, "conversation_batches", column, statement); err != nil {
			return err
		}
	}
	campaignTaskColumns := map[string]string{
		"parent_task_id":  "ALTER TABLE campaign_tasks ADD COLUMN parent_task_id TEXT NOT NULL DEFAULT ''",
		"source_type":     "ALTER TABLE campaign_tasks ADD COLUMN source_type TEXT NOT NULL DEFAULT ''",
		"source_ref":      "ALTER TABLE campaign_tasks ADD COLUMN source_ref TEXT NOT NULL DEFAULT ''",
		"intent_json":     "ALTER TABLE campaign_tasks ADD COLUMN intent_json TEXT NOT NULL DEFAULT '{}'",
		"next_attempt_at": "ALTER TABLE campaign_tasks ADD COLUMN next_attempt_at INTEGER NOT NULL DEFAULT 0",
		"failure_kind":    "ALTER TABLE campaign_tasks ADD COLUMN failure_kind TEXT NOT NULL DEFAULT ''",
	}
	for column, statement := range campaignTaskColumns {
		if err := db.ensureColumn(ctx, "campaign_tasks", column, statement); err != nil {
			return err
		}
	}
	if _, err := db.ExecContext(
		ctx,
		`CREATE INDEX IF NOT EXISTS idx_campaign_tasks_source_campaign
		 ON campaign_tasks(source_type, campaign_id)`,
	); err != nil {
		return err
	}
	campaignGroupColumns := map[string]string{
		"business_system":     "ALTER TABLE campaign_groups ADD COLUMN business_system TEXT NOT NULL DEFAULT ''",
		"business_priority":   "ALTER TABLE campaign_groups ADD COLUMN business_priority INTEGER NOT NULL DEFAULT 50",
		"priority_score":      "ALTER TABLE campaign_groups ADD COLUMN priority_score INTEGER NOT NULL DEFAULT 50",
		"priority_reason":     "ALTER TABLE campaign_groups ADD COLUMN priority_reason TEXT NOT NULL DEFAULT ''",
		"priority_updated_at": "ALTER TABLE campaign_groups ADD COLUMN priority_updated_at INTEGER NOT NULL DEFAULT 0",
	}
	for column, statement := range campaignGroupColumns {
		if err := db.ensureColumn(ctx, "campaign_groups", column, statement); err != nil {
			return err
		}
	}
	campaignFrontierColumns := map[string]string{
		"expected_value": "ALTER TABLE campaign_frontier ADD COLUMN expected_value INTEGER NOT NULL DEFAULT 50",
		"estimated_cost": "ALTER TABLE campaign_frontier ADD COLUMN estimated_cost INTEGER NOT NULL DEFAULT 1",
		"roi":            "ALTER TABLE campaign_frontier ADD COLUMN roi INTEGER NOT NULL DEFAULT 50",
	}
	for column, statement := range campaignFrontierColumns {
		if err := db.ensureColumn(ctx, "campaign_frontier", column, statement); err != nil {
			return err
		}
	}
	if _, err := db.ExecContext(
		ctx,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_campaign_tasks_asset_kind
		 ON campaign_tasks(campaign_id, asset_id, kind, source_ref)`,
	); err != nil {
		return err
	}
	summaryColumns := map[string]string{
		"version":         "ALTER TABLE conversation_summaries ADD COLUMN version INTEGER NOT NULL DEFAULT 0",
		"token_before":    "ALTER TABLE conversation_summaries ADD COLUMN token_before INTEGER NOT NULL DEFAULT 0",
		"token_after":     "ALTER TABLE conversation_summaries ADD COLUMN token_after INTEGER NOT NULL DEFAULT 0",
		"transcript_path": "ALTER TABLE conversation_summaries ADD COLUMN transcript_path TEXT NOT NULL DEFAULT ''",
	}
	for column, statement := range summaryColumns {
		if err := db.ensureColumn(ctx, "conversation_summaries", column, statement); err != nil {
			return err
		}
	}
	tokenUsageColumns := map[string]string{
		"project_id":        "ALTER TABLE token_usage ADD COLUMN project_id TEXT NOT NULL DEFAULT ''",
		"kind":              "ALTER TABLE token_usage ADD COLUMN kind TEXT NOT NULL DEFAULT 'chat'",
		"model":             "ALTER TABLE token_usage ADD COLUMN model TEXT NOT NULL DEFAULT ''",
		"cache_read_tokens": "ALTER TABLE token_usage ADD COLUMN cache_read_tokens INTEGER NOT NULL DEFAULT 0",
	}
	for column, statement := range tokenUsageColumns {
		if err := db.ensureColumn(ctx, "token_usage", column, statement); err != nil {
			return err
		}
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE token_usage
			 SET project_id = (
				SELECT conversations.project_id
				FROM conversations
				WHERE conversations.id = token_usage.conversation_id
				  AND conversations.owner_user_id = token_usage.user_id
			 )
			 WHERE project_id = ''
			   AND EXISTS (
				SELECT 1
				FROM conversations
				WHERE conversations.id = token_usage.conversation_id
				  AND conversations.owner_user_id = token_usage.user_id
			 )`,
	); err != nil {
		return fmt.Errorf("backfill token_usage.project_id: %w", err)
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS idx_token_usage_project
			 ON token_usage(project_id, user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_token_usage_conversation
			 ON token_usage(conversation_id)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if err := db.ensureColumn(
		ctx,
		"context_compactions",
		"kind",
		"ALTER TABLE context_compactions ADD COLUMN kind TEXT NOT NULL DEFAULT 'major'",
	); err != nil {
		return err
	}
	memoryWriteColumns := map[string]string{
		"before_key":      "ALTER TABLE memory_writes ADD COLUMN before_key TEXT NOT NULL DEFAULT ''",
		"after_key":       "ALTER TABLE memory_writes ADD COLUMN after_key TEXT NOT NULL DEFAULT ''",
		"related_fact_id": "ALTER TABLE memory_writes ADD COLUMN related_fact_id TEXT NOT NULL DEFAULT ''",
	}
	for column, statement := range memoryWriteColumns {
		if err := db.ensureColumn(ctx, "memory_writes", column, statement); err != nil {
			return err
		}
	}
	projectFactColumns := map[string]string{
		"asset_id":         "ALTER TABLE project_facts ADD COLUMN asset_id TEXT NOT NULL DEFAULT ''",
		"summary":          "ALTER TABLE project_facts ADD COLUMN summary TEXT NOT NULL DEFAULT ''",
		"body":             "ALTER TABLE project_facts ADD COLUMN body TEXT NOT NULL DEFAULT ''",
		"evidence":         "ALTER TABLE project_facts ADD COLUMN evidence TEXT NOT NULL DEFAULT ''",
		"relation":         "ALTER TABLE project_facts ADD COLUMN relation TEXT NOT NULL DEFAULT ''",
		"source_type":      "ALTER TABLE project_facts ADD COLUMN source_type TEXT NOT NULL DEFAULT ''",
		"source_id":        "ALTER TABLE project_facts ADD COLUMN source_id TEXT NOT NULL DEFAULT ''",
		"valid_from":       "ALTER TABLE project_facts ADD COLUMN valid_from INTEGER NOT NULL DEFAULT 0",
		"valid_to":         "ALTER TABLE project_facts ADD COLUMN valid_to INTEGER NOT NULL DEFAULT 0",
		"superseded_by":    "ALTER TABLE project_facts ADD COLUMN superseded_by TEXT NOT NULL DEFAULT ''",
		"importance":       "ALTER TABLE project_facts ADD COLUMN importance INTEGER NOT NULL DEFAULT 50",
		"version":          "ALTER TABLE project_facts ADD COLUMN version INTEGER NOT NULL DEFAULT 1",
		"embedding":        "ALTER TABLE project_facts ADD COLUMN embedding BLOB",
		"embedding_model":  "ALTER TABLE project_facts ADD COLUMN embedding_model TEXT NOT NULL DEFAULT ''",
		"last_used_at":     "ALTER TABLE project_facts ADD COLUMN last_used_at INTEGER NOT NULL DEFAULT 0",
		"use_count":        "ALTER TABLE project_facts ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0",
		"tainted":          "ALTER TABLE project_facts ADD COLUMN tainted INTEGER NOT NULL DEFAULT 0",
		"taint_reason":     "ALTER TABLE project_facts ADD COLUMN taint_reason TEXT NOT NULL DEFAULT ''",
		"memory_kind":      "ALTER TABLE project_facts ADD COLUMN memory_kind TEXT NOT NULL DEFAULT 'general'",
		"priority":         "ALTER TABLE project_facts ADD COLUMN priority INTEGER NOT NULL DEFAULT 50",
		"pinned":           "ALTER TABLE project_facts ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0",
		"observed_at":      "ALTER TABLE project_facts ADD COLUMN observed_at INTEGER NOT NULL DEFAULT 0",
		"contradicted_by":  "ALTER TABLE project_facts ADD COLUMN contradicted_by TEXT NOT NULL DEFAULT ''",
		"conflict_reason":  "ALTER TABLE project_facts ADD COLUMN conflict_reason TEXT NOT NULL DEFAULT ''",
		"subject_type":     "ALTER TABLE project_facts ADD COLUMN subject_type TEXT NOT NULL DEFAULT ''",
		"subject_key":      "ALTER TABLE project_facts ADD COLUMN subject_key TEXT NOT NULL DEFAULT ''",
		"predicate":        "ALTER TABLE project_facts ADD COLUMN predicate TEXT NOT NULL DEFAULT ''",
		"object_type":      "ALTER TABLE project_facts ADD COLUMN object_type TEXT NOT NULL DEFAULT ''",
		"object_key":       "ALTER TABLE project_facts ADD COLUMN object_key TEXT NOT NULL DEFAULT ''",
		"fact_fingerprint": "ALTER TABLE project_facts ADD COLUMN fact_fingerprint TEXT NOT NULL DEFAULT ''",
	}
	for column, statement := range projectFactColumns {
		if err := db.ensureColumn(ctx, "project_facts", column, statement); err != nil {
			return err
		}
	}
	if _, err := db.ExecContext(
		ctx,
		`CREATE INDEX IF NOT EXISTS idx_project_facts_fingerprint
		 ON project_facts(project_id, asset_id, fact_fingerprint)`,
	); err != nil {
		return err
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE project_facts
		 SET asset_id = COALESCE((
		 	SELECT c.asset_id FROM conversations c
		 	WHERE c.id = project_facts.source_id
		 	  AND c.asset_id <> ''
		 	LIMIT 1
		 ), asset_id)
		 WHERE asset_id = ''
		   AND source_type = 'conversation'
		   AND source_id <> ''`,
	); err != nil {
		return err
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE project_facts
		 SET asset_id = COALESCE((
		 	SELECT a.id FROM assets a
		 	WHERE a.project_id = project_facts.project_id
		 	  AND instr(project_facts.relation, 'asset:' || a.id) > 0
		 	ORDER BY a.updated_at DESC, a.id ASC
		 	LIMIT 1
		 ), asset_id)
		 WHERE asset_id = ''
		   AND relation <> ''`,
	); err != nil {
		return err
	}
	for _, statement := range []string{
		`DROP INDEX IF EXISTS idx_project_facts_project_key`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_project_facts_scope_key
			 ON project_facts(project_id, asset_id, key)`,
		`CREATE INDEX IF NOT EXISTS idx_project_facts_asset
			 ON project_facts(project_id, asset_id, updated_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_conversations_asset
			 ON conversations(project_id, asset_id, updated_at DESC)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if _, err := db.ExecContext(
		ctx,
		`CREATE INDEX IF NOT EXISTS idx_project_facts_priority
		 ON project_facts(project_id, priority DESC, updated_at DESC)`,
	); err != nil {
		return err
	}
	vulnerabilityColumns := map[string]string{
		"vulnerability_type": "ALTER TABLE vulnerabilities ADD COLUMN vulnerability_type TEXT NOT NULL DEFAULT ''",
		"target":             "ALTER TABLE vulnerabilities ADD COLUMN target TEXT NOT NULL DEFAULT ''",
		"parameter":          "ALTER TABLE vulnerabilities ADD COLUMN parameter TEXT NOT NULL DEFAULT ''",
		"http_method":        "ALTER TABLE vulnerabilities ADD COLUMN http_method TEXT NOT NULL DEFAULT ''",
		"preconditions":      "ALTER TABLE vulnerabilities ADD COLUMN preconditions TEXT NOT NULL DEFAULT ''",
		"reproduction_steps": "ALTER TABLE vulnerabilities ADD COLUMN reproduction_steps TEXT NOT NULL DEFAULT ''",
		"impact":             "ALTER TABLE vulnerabilities ADD COLUMN impact TEXT NOT NULL DEFAULT ''",
		"evidence_refs":      "ALTER TABLE vulnerabilities ADD COLUMN evidence_refs TEXT NOT NULL DEFAULT '[]'",
		"recommendation":     "ALTER TABLE vulnerabilities ADD COLUMN recommendation TEXT NOT NULL DEFAULT ''",
		"retest_notes":       "ALTER TABLE vulnerabilities ADD COLUMN retest_notes TEXT NOT NULL DEFAULT ''",
		"fingerprint":        "ALTER TABLE vulnerabilities ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''",
		"verification_state": "ALTER TABLE vulnerabilities ADD COLUMN verification_state TEXT NOT NULL DEFAULT 'unverified'",
		"confidence":         "ALTER TABLE vulnerabilities ADD COLUMN confidence INTEGER NOT NULL DEFAULT 0",
		"exploitability":     "ALTER TABLE vulnerabilities ADD COLUMN exploitability TEXT NOT NULL DEFAULT ''",
		"test_technique":     "ALTER TABLE vulnerabilities ADD COLUMN test_technique TEXT NOT NULL DEFAULT ''",
	}
	for column, statement := range vulnerabilityColumns {
		if err := db.ensureColumn(ctx, "vulnerabilities", column, statement); err != nil {
			return err
		}
	}
	mcpToolColumns := map[string]string{
		"capability": "ALTER TABLE mcp_tool_settings ADD COLUMN capability TEXT NOT NULL DEFAULT 'destructive'",
	}
	for column, statement := range mcpToolColumns {
		if err := db.ensureColumn(ctx, "mcp_tool_settings", column, statement); err != nil {
			return err
		}
	}
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_fingerprint
			 ON vulnerabilities(project_id, fingerprint)`,
		`CREATE TABLE IF NOT EXISTS vulnerability_fingerprints (
				project_id TEXT NOT NULL,
				owner_user_id TEXT NOT NULL,
				fingerprint TEXT NOT NULL,
				vulnerability_id TEXT NOT NULL,
				created_at INTEGER NOT NULL,
				updated_at INTEGER NOT NULL,
				PRIMARY KEY (project_id, owner_user_id, fingerprint)
			)`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerability_fingerprints_vulnerability
			 ON vulnerability_fingerprints(vulnerability_id)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	testResultColumns := map[string]string{
		"rationale":         "ALTER TABLE project_test_results ADD COLUMN rationale TEXT NOT NULL DEFAULT ''",
		"expected_evidence": "ALTER TABLE project_test_results ADD COLUMN expected_evidence TEXT NOT NULL DEFAULT ''",
		"priority":          "ALTER TABLE project_test_results ADD COLUMN priority INTEGER NOT NULL DEFAULT 0",
		"parent_finding_id": "ALTER TABLE project_test_results ADD COLUMN parent_finding_id TEXT NOT NULL DEFAULT ''",
		"attempts":          "ALTER TABLE project_test_results ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0",
		"required":          "ALTER TABLE project_test_results ADD COLUMN required INTEGER NOT NULL DEFAULT 1",
	}
	for column, statement := range testResultColumns {
		if err := db.ensureColumn(ctx, "project_test_results", column, statement); err != nil {
			return err
		}
	}
	if _, err := db.ExecContext(
		ctx,
		`CREATE INDEX IF NOT EXISTS idx_project_test_results_priority
		 ON project_test_results(project_id, priority DESC, updated_at DESC)`,
	); err != nil {
		return err
	}
	retestColumns := map[string]string{
		"status":                  "ALTER TABLE vulnerability_retests ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'",
		"conversation_id":         "ALTER TABLE vulnerability_retests ADD COLUMN conversation_id TEXT NOT NULL DEFAULT ''",
		"task_id":                 "ALTER TABLE vulnerability_retests ADD COLUMN task_id TEXT NOT NULL DEFAULT ''",
		"source_conversation_ids": "ALTER TABLE vulnerability_retests ADD COLUMN source_conversation_ids TEXT NOT NULL DEFAULT '[]'",
		"started_at":              "ALTER TABLE vulnerability_retests ADD COLUMN started_at INTEGER NOT NULL DEFAULT 0",
		"completed_at":            "ALTER TABLE vulnerability_retests ADD COLUMN completed_at INTEGER NOT NULL DEFAULT 0",
		"error":                   "ALTER TABLE vulnerability_retests ADD COLUMN error TEXT NOT NULL DEFAULT ''",
	}
	for column, statement := range retestColumns {
		if err := db.ensureColumn(ctx, "vulnerability_retests", column, statement); err != nil {
			return err
		}
	}
	graphColumns := map[string]string{
		"source_ref_id": "ALTER TABLE project_graph_nodes ADD COLUMN source_ref_id TEXT NOT NULL DEFAULT ''",
		"pos_x":         "ALTER TABLE project_graph_nodes ADD COLUMN pos_x INTEGER NOT NULL DEFAULT 0",
		"pos_y":         "ALTER TABLE project_graph_nodes ADD COLUMN pos_y INTEGER NOT NULL DEFAULT 0",
	}
	for column, statement := range graphColumns {
		if err := db.ensureColumn(ctx, "project_graph_nodes", column, statement); err != nil {
			return err
		}
	}
	for _, statement := range []string{
		`DROP INDEX IF EXISTS idx_project_graph_nodes_unique`,
		`DROP INDEX IF EXISTS idx_project_graph_nodes_ref_unique`,
		`DROP INDEX IF EXISTS idx_project_graph_nodes_title_unique`,
		`DROP INDEX IF EXISTS idx_project_graph_edges_unique`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	// 为历史自动同步的 finding 节点回填稳定漏洞 ID；同标题重复漏洞暂取最早一条，
	// 后续同步会为其余漏洞创建各自的稳定节点。
	if _, err := db.ExecContext(
		ctx,
		`UPDATE project_graph_nodes
		 SET source_ref_id = COALESCE((
		 	SELECT v.id FROM vulnerabilities v
		 	WHERE v.project_id = project_graph_nodes.project_id
		 	  AND v.title = project_graph_nodes.title
		 	ORDER BY v.created_at ASC, v.id ASC
		 	LIMIT 1
		 ), source_ref_id)
		 WHERE kind = 'finding'
		   AND TRIM(source_ref_id) = ''`,
	); err != nil {
		return err
	}
	projectColumns := map[string]string{
		"goals":  "ALTER TABLE projects ADD COLUMN goals TEXT NOT NULL DEFAULT ''",
		"scope":  "ALTER TABLE projects ADD COLUMN scope TEXT NOT NULL DEFAULT ''",
		"status": "ALTER TABLE projects ADD COLUMN status TEXT NOT NULL DEFAULT 'active'",
	}
	for column, statement := range projectColumns {
		if err := db.ensureColumn(ctx, "projects", column, statement); err != nil {
			return err
		}
	}
	// 先回填历史资产归属，再清理图节点并创建资产维度唯一索引。
	// 否则两个未归属节点在回填到同一资产后可能撞上唯一索引。
	if err := db.backfillProjectAssets(ctx); err != nil {
		return err
	}
	// 把项目「资产范围」文本同步为可执行资产，保证升级后 Policy Engine 立即生效。
	if err := db.backfillProjectScopeAssets(ctx); err != nil {
		return err
	}
	// 修复项目级后台会话缺失的 Campaign 授权资产映射。
	if err := db.backfillProjectSessionCampaignEndpoints(ctx); err != nil {
		return err
	}
	if err := db.recoverDraftProjectSessionCampaigns(ctx); err != nil {
		return err
	}
	// 清理历史重复的攻击路径节点/连线并建立唯一索引（并发同步曾产生重复）。
	if err := db.dedupeProjectGraph(ctx); err != nil {
		return err
	}
	if err := db.cleanupOrphanProjectData(ctx); err != nil {
		return err
	}
	// 旧版事实只有 value，迁移后用 value 回填摘要索引。
	if _, err := db.ExecContext(
		ctx,
		`UPDATE project_facts SET summary = value WHERE TRIM(summary) = ''`,
	); err != nil {
		return err
	}
	// 统一漏洞状态口径：历史数据可能写入 pending 或空值，前端与统计只认 open/confirmed/...
	if _, err := db.ExecContext(
		ctx,
		`UPDATE vulnerabilities SET status = 'open'
		 WHERE TRIM(status) = '' OR status = 'pending'`,
	); err != nil {
		return err
	}
	// 历史漏洞回填验证状态：确认且存在证据的记录视为已验证，其余按证据情况降级。
	if _, err := db.ExecContext(
		ctx,
		`UPDATE vulnerabilities
		 SET verification_state = CASE
		 	WHEN status IN ('confirmed', 'fixed')
		 		AND (TRIM(evidence) <> '' OR TRIM(evidence_refs) NOT IN ('', '[]'))
		 		THEN 'verified'
		 	WHEN TRIM(evidence) <> '' OR TRIM(evidence_refs) NOT IN ('', '[]')
		 		THEN 'observed'
		 	ELSE 'unverified'
		 END,
		 confidence = CASE
		 	WHEN status IN ('confirmed', 'fixed')
		 		AND (TRIM(evidence) <> '' OR TRIM(evidence_refs) NOT IN ('', '[]'))
		 		THEN 80
		 	WHEN TRIM(evidence) <> '' OR TRIM(evidence_refs) NOT IN ('', '[]')
		 		THEN 60
		 	ELSE confidence
		 END
		 WHERE confidence = 0 AND verification_state = 'unverified'`,
	); err != nil {
		return err
	}
	return nil
}

func (db *DB) ensureColumn(
	ctx context.Context,
	table string,
	column string,
	statement string,
) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name string
		var columnType string
		var notNull int
		var defaultValue interface{}
		var primaryKey int
		if err := rows.Scan(
			&cid,
			&name,
			&columnType,
			&notNull,
			&defaultValue,
			&primaryKey,
		); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("add column %s.%s: %w", table, column, err)
	}
	return nil
}

func (db *DB) CountUsers(ctx context.Context) (int, error) {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (db *DB) CreateUser(ctx context.Context, user User) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO users (
			id, username, display_name, password_hash, role, enabled, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		user.ID,
		user.Username,
		user.DisplayName,
		user.PasswordHash,
		user.Role,
		boolToInt(user.Enabled),
		user.CreatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func (db *DB) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, username, display_name, password_hash, role, enabled, created_at
		 FROM users WHERE username = ?`,
		username,
	)
	return scanUser(row)
}

func (db *DB) GetUserByID(ctx context.Context, id string) (*User, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, username, display_name, password_hash, role, enabled, created_at
		 FROM users WHERE id = ?`,
		id,
	)
	return scanUser(row)
}

func (db *DB) CreateSession(ctx context.Context, session Session) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO sessions (
			id, user_id, token_hash, csrf_hash, expires_at, created_at, last_seen_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		session.ID,
		session.UserID,
		session.TokenHash,
		session.CSRFHash,
		session.ExpiresAt.Unix(),
		session.CreatedAt.Unix(),
		session.LastSeenAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (db *DB) GetSession(ctx context.Context, tokenHash string) (*Session, *User, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT
			s.id, s.user_id, s.token_hash, s.csrf_hash,
			s.expires_at, s.created_at, s.last_seen_at,
			u.id, u.username, u.display_name, u.password_hash, u.role, u.enabled, u.created_at
		 FROM sessions s
		 JOIN users u ON u.id = s.user_id
		 WHERE s.token_hash = ?`,
		tokenHash,
	)

	var session Session
	var user User
	var expiresAt int64
	var createdAt int64
	var lastSeenAt int64
	var userCreatedAt int64
	var enabled int

	err := row.Scan(
		&session.ID,
		&session.UserID,
		&session.TokenHash,
		&session.CSRFHash,
		&expiresAt,
		&createdAt,
		&lastSeenAt,
		&user.ID,
		&user.Username,
		&user.DisplayName,
		&user.PasswordHash,
		&user.Role,
		&enabled,
		&userCreatedAt,
	)
	if err != nil {
		return nil, nil, err
	}

	session.ExpiresAt = time.Unix(expiresAt, 0)
	session.CreatedAt = time.Unix(createdAt, 0)
	session.LastSeenAt = time.Unix(lastSeenAt, 0)
	user.Enabled = enabled != 0
	user.CreatedAt = time.Unix(userCreatedAt, 0)

	return &session, &user, nil
}

func (db *DB) TouchSession(ctx context.Context, id string, at time.Time) error {
	_, err := db.ExecContext(
		ctx,
		`UPDATE sessions SET last_seen_at = ? WHERE id = ?`,
		at.Unix(),
		id,
	)
	return err
}

func (db *DB) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (db *DB) DeleteOtherSessions(ctx context.Context, userID, keepTokenHash string) error {
	_, err := db.ExecContext(
		ctx,
		`DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?`,
		userID,
		keepTokenHash,
	)
	return err
}

const sessionCleanupBatchSize = 1000

func (db *DB) DeleteExpiredSessions(ctx context.Context, at time.Time) (int64, error) {
	cutoff := at.Unix()
	var total int64
	for {
		result, err := db.ExecContext(
			ctx,
			`DELETE FROM sessions
			 WHERE id IN (
				SELECT id FROM sessions
				WHERE expires_at <= ?
				ORDER BY expires_at ASC
				LIMIT ?
			 )`,
			cutoff,
			sessionCleanupBatchSize,
		)
		if err != nil {
			return total, err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return total, err
		}
		total += affected
		if affected < sessionCleanupBatchSize {
			return total, nil
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (db *DB) dropColumnIfExists(ctx context.Context, table, column string) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return err
		}
		if strings.EqualFold(name, column) {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	if !found {
		return nil
	}
	_, err = db.ExecContext(ctx, `ALTER TABLE `+table+` DROP COLUMN `+column)
	return err
}

func scanUser(row *sql.Row) (*User, error) {
	var user User
	var enabled int
	var createdAt int64
	if err := row.Scan(
		&user.ID,
		&user.Username,
		&user.DisplayName,
		&user.PasswordHash,
		&user.Role,
		&enabled,
		&createdAt,
	); err != nil {
		return nil, err
	}
	user.Enabled = enabled != 0
	user.CreatedAt = time.Unix(createdAt, 0)
	return &user, nil
}

func IsNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
