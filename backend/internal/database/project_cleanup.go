package database

import "context"

func (db *DB) cleanupOrphanProjectData(ctx context.Context) error {
	statements := []string{
		`DELETE FROM project_graph_edges
		 WHERE project_id <> '' AND NOT EXISTS (
			SELECT 1 FROM projects WHERE projects.id = project_graph_edges.project_id
		 )`,
		`DELETE FROM project_graph_nodes
		 WHERE project_id <> '' AND NOT EXISTS (
			SELECT 1 FROM projects WHERE projects.id = project_graph_nodes.project_id
		 )`,
		`DELETE FROM project_facts
		 WHERE project_id <> '' AND NOT EXISTS (
			SELECT 1 FROM projects WHERE projects.id = project_facts.project_id
		 )`,
		`DELETE FROM assets
		 WHERE project_id <> '' AND NOT EXISTS (
			SELECT 1 FROM projects WHERE projects.id = assets.project_id
		 )`,
		`DELETE FROM vulnerabilities
		 WHERE project_id <> '' AND NOT EXISTS (
			SELECT 1 FROM projects WHERE projects.id = vulnerabilities.project_id
		 )`,
		`DELETE FROM conversation_batches
		 WHERE project_id <> '' AND NOT EXISTS (
			SELECT 1 FROM projects WHERE projects.id = conversation_batches.project_id
		 )`,
		`DELETE FROM campaign_chain_steps
		 WHERE chain_id <> '' AND NOT EXISTS (
			SELECT 1 FROM campaign_chains WHERE campaign_chains.id = campaign_chain_steps.chain_id
		 )`,
		`DELETE FROM campaign_chains
		 WHERE campaign_id <> '' AND NOT EXISTS (
			SELECT 1 FROM conversation_batches WHERE conversation_batches.id = campaign_chains.campaign_id
		 )`,
		`DELETE FROM campaign_memory_digests
		 WHERE campaign_id <> '' AND NOT EXISTS (
			SELECT 1 FROM conversation_batches WHERE conversation_batches.id = campaign_memory_digests.campaign_id
		 )`,
		`DELETE FROM campaign_verifications
		 WHERE campaign_id <> '' AND NOT EXISTS (
			SELECT 1 FROM conversation_batches WHERE conversation_batches.id = campaign_verifications.campaign_id
		 )`,
		`DELETE FROM campaign_links
		 WHERE campaign_id <> '' AND NOT EXISTS (
			SELECT 1 FROM conversation_batches WHERE conversation_batches.id = campaign_links.campaign_id
		 )`,
		`DELETE FROM campaign_frontier
		 WHERE campaign_id <> '' AND NOT EXISTS (
			SELECT 1 FROM conversation_batches WHERE conversation_batches.id = campaign_frontier.campaign_id
		 )`,
		`DELETE FROM campaign_tasks
		 WHERE project_id <> '' AND NOT EXISTS (
			SELECT 1 FROM projects WHERE projects.id = campaign_tasks.project_id
		 )`,
		`DELETE FROM campaign_frontier
		 WHERE task_id <> '' AND NOT EXISTS (
			SELECT 1 FROM campaign_tasks WHERE campaign_tasks.id = campaign_frontier.task_id
		 )`,
		`DELETE FROM campaign_endpoints
		 WHERE project_id <> '' AND NOT EXISTS (
			SELECT 1 FROM projects WHERE projects.id = campaign_endpoints.project_id
		 )`,
		`DELETE FROM campaign_groups
		 WHERE project_id <> '' AND NOT EXISTS (
			SELECT 1 FROM projects WHERE projects.id = campaign_groups.project_id
		 )`,
		`DELETE FROM campaign_coverage
		 WHERE campaign_id <> '' AND NOT EXISTS (
			SELECT 1 FROM conversation_batches WHERE conversation_batches.id = campaign_coverage.campaign_id
		 )`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}
