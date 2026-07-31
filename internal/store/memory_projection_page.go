package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/l33tdawg/sage/internal/memory"
)

const defaultMemoryProjectionPageSize = 512
const maxMemoryProjectionPageSize = 1024

func normalizeMemoryProjectionPage(
	after MemoryProjectionPageCursor,
	limit int,
) (MemoryProjectionPageCursor, int, error) {
	if (after.CreatedAt == "") != (after.MemoryID == "") {
		return MemoryProjectionPageCursor{}, 0,
			fmt.Errorf("memory projection cursor requires created_at and memory_id together")
	}
	if limit <= 0 || limit > maxMemoryProjectionPageSize {
		limit = defaultMemoryProjectionPageSize
	}
	return after, limit, nil
}

func appendSQLiteMemoryProjectionFilters(
	query string,
	opts ListOptions,
) (string, []any) {
	args := make([]any, 0)
	add := func(clause string, values ...any) {
		query += clause
		args = append(args, values...)
	}
	if opts.DomainTag != "" {
		add(" AND domain_tag = ?", opts.DomainTag)
	}
	for _, prefix := range opts.ExcludeDomainPrefixes {
		if prefix != "" {
			add(" AND LOWER(domain_tag) NOT LIKE ?", strings.ToLower(prefix)+"%")
		}
	}
	if opts.Provider != "" {
		add(" AND (provider = ? OR provider = '' OR memory_type = 'fact')", opts.Provider)
	}
	switch {
	case opts.Status == "active":
		query += " AND status != 'deprecated'"
	case opts.Status != "":
		add(" AND status = ?", opts.Status)
	}
	if opts.SubmittingAgent != "" {
		add(" AND submitting_agent = ?", opts.SubmittingAgent)
	}
	if opts.Tag != "" {
		add(" AND memory_id IN (SELECT memory_id FROM memory_tags WHERE tag = ?)", opts.Tag)
	}
	if opts.CreatedFrom != "" {
		add(" AND created_at >= ?", opts.CreatedFrom)
	}
	if opts.CreatedTo != "" {
		add(" AND created_at <= ?", opts.CreatedTo)
	}
	if len(opts.SubmittingAgents) > 0 {
		placeholders := make([]string, len(opts.SubmittingAgents))
		for i, agentID := range opts.SubmittingAgents {
			placeholders[i] = "?"
			args = append(args, agentID)
		}
		query += " AND submitting_agent IN (" + strings.Join(placeholders, ",") + ")"
	}
	return query, args
}

// ListMemoryProjectionPage walks the SQLite memory projection without a
// COUNT(*) or OFFSET. It deliberately selects the same portable fields as
// ListMemories; embeddings remain outside the canonical projection audit.
func (s *SQLiteStore) ListMemoryProjectionPage(
	ctx context.Context,
	opts ListOptions,
	after MemoryProjectionPageCursor,
	limit int,
) ([]*memory.MemoryRecord, MemoryProjectionPageCursor, error) {
	if s == nil || s.conn == nil {
		return nil, MemoryProjectionPageCursor{},
			fmt.Errorf("memory projection pager is unavailable")
	}
	after, limit, err := normalizeMemoryProjectionPage(after, limit)
	if err != nil {
		return nil, MemoryProjectionPageCursor{}, err
	}
	query := `SELECT memory_id, submitting_agent, content, content_hash,
		memory_type, domain_tag, provider, confidence_score, status, parent_hash, created_at,
		committed_at, deprecated_at, COALESCE(task_status, '')
		FROM memories WHERE 1=1`
	query, args := appendSQLiteMemoryProjectionFilters(query, opts)
	if after.MemoryID != "" {
		query += " AND (created_at > ? OR (created_at = ? AND memory_id > ?))"
		args = append(args, after.CreatedAt, after.CreatedAt, after.MemoryID)
	}
	query += " ORDER BY created_at ASC, memory_id ASC LIMIT ?"
	args = append(args, limit)

	rows, err := s.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, MemoryProjectionPageCursor{},
			fmt.Errorf("list memory projection page: %w", err)
	}
	defer func() { _ = rows.Close() }()

	records := make([]*memory.MemoryRecord, 0, limit)
	next := MemoryProjectionPageCursor{}
	for rows.Next() {
		var (
			record                            memory.MemoryRecord
			memoryType, status, createdAt     string
			taskStatus                        string
			parentHash, committed, deprecated *string
		)
		if err := rows.Scan(
			&record.MemoryID,
			&record.SubmittingAgent,
			&record.Content,
			&record.ContentHash,
			&memoryType,
			&record.DomainTag,
			&record.Provider,
			&record.ConfidenceScore,
			&status,
			&parentHash,
			&createdAt,
			&committed,
			&deprecated,
			&taskStatus,
		); err != nil {
			return nil, MemoryProjectionPageCursor{},
				fmt.Errorf("scan memory projection page: %w", err)
		}
		record.MemoryType = memory.MemoryType(memoryType)
		record.Status = memory.MemoryStatus(status)
		record.TaskStatus = memory.TaskStatus(taskStatus)
		record.CreatedAt = parseTime(createdAt)
		record.CommittedAt = parseTimePtr(committed)
		record.DeprecatedAt = parseTimePtr(deprecated)
		if parentHash != nil {
			record.ParentHash = *parentHash
		}
		if plaintext, decryptErr := s.decryptContent(record.Content); decryptErr == nil {
			record.Content = plaintext
		}
		records = append(records, &record)
		next = MemoryProjectionPageCursor{
			CreatedAt: createdAt,
			MemoryID:  record.MemoryID,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, MemoryProjectionPageCursor{},
			fmt.Errorf("walk memory projection page: %w", err)
	}
	return records, next, nil
}

func appendPostgresMemoryProjectionFilters(
	query string,
	opts ListOptions,
	args []any,
) (string, []any) {
	add := func(clause string, value any) {
		query += fmt.Sprintf(clause, len(args)+1)
		args = append(args, value)
	}
	if opts.DomainTag != "" {
		add(" AND domain_tag = $%d", opts.DomainTag)
	}
	for _, prefix := range opts.ExcludeDomainPrefixes {
		if prefix != "" {
			add(" AND LOWER(domain_tag) NOT LIKE $%d", strings.ToLower(prefix)+"%")
		}
	}
	if opts.Provider != "" {
		add(" AND (provider = $%d OR provider = '' OR memory_type = 'fact')", opts.Provider)
	}
	switch {
	case opts.Status == "active":
		query += " AND status != 'deprecated'"
	case opts.Status != "":
		add(" AND status = $%d", opts.Status)
	}
	if opts.SubmittingAgent != "" {
		add(" AND submitting_agent = $%d", opts.SubmittingAgent)
	}
	if opts.Tag != "" {
		add(" AND EXISTS (SELECT 1 FROM memory_tags mt WHERE mt.memory_id = memories.memory_id AND mt.tag = $%d)", opts.Tag)
	}
	if opts.CreatedFrom != "" {
		add(" AND created_at >= $%d::timestamptz", opts.CreatedFrom)
	}
	if opts.CreatedTo != "" {
		add(" AND created_at <= $%d::timestamptz", opts.CreatedTo)
	}
	if len(opts.SubmittingAgents) > 0 {
		placeholders := make([]string, len(opts.SubmittingAgents))
		for i, agentID := range opts.SubmittingAgents {
			placeholders[i] = fmt.Sprintf("$%d", len(args)+1)
			args = append(args, agentID)
		}
		query += " AND submitting_agent IN (" + strings.Join(placeholders, ",") + ")"
	}
	return query, args
}

// ListMemoryProjectionPage is the PostgreSQL parity path for complete
// projection audits. It avoids both COUNT(*) and large OFFSET scans.
func (s *PostgresStore) ListMemoryProjectionPage(
	ctx context.Context,
	opts ListOptions,
	after MemoryProjectionPageCursor,
	limit int,
) ([]*memory.MemoryRecord, MemoryProjectionPageCursor, error) {
	if s == nil || s.db == nil {
		return nil, MemoryProjectionPageCursor{},
			fmt.Errorf("memory projection pager is unavailable")
	}
	after, limit, err := normalizeMemoryProjectionPage(after, limit)
	if err != nil {
		return nil, MemoryProjectionPageCursor{}, err
	}
	query := `SELECT memory_id, submitting_agent, content, content_hash,
		memory_type, domain_tag, provider, confidence_score, status, parent_hash, created_at,
		committed_at, deprecated_at, COALESCE(task_status, '')
		FROM memories WHERE 1=1`
	args := make([]any, 0)
	query, args = appendPostgresMemoryProjectionFilters(query, opts, args)
	if after.MemoryID != "" {
		createdArg := len(args) + 1
		memoryArg := createdArg + 1
		query += fmt.Sprintf(
			" AND (created_at > $%d::timestamptz OR (created_at = $%d::timestamptz AND memory_id > $%d::uuid))",
			createdArg, createdArg, memoryArg,
		)
		args = append(args, after.CreatedAt, after.MemoryID)
	}
	query += fmt.Sprintf(
		" ORDER BY created_at ASC, memory_id ASC LIMIT $%d",
		len(args)+1,
	)
	args = append(args, limit)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, MemoryProjectionPageCursor{},
			fmt.Errorf("list memory projection page: %w", err)
	}
	defer rows.Close()

	records := make([]*memory.MemoryRecord, 0, limit)
	next := MemoryProjectionPageCursor{}
	for rows.Next() {
		var (
			record                         memory.MemoryRecord
			memoryType, status, taskStatus string
			parentHash                     *string
		)
		if err := rows.Scan(
			&record.MemoryID,
			&record.SubmittingAgent,
			&record.Content,
			&record.ContentHash,
			&memoryType,
			&record.DomainTag,
			&record.Provider,
			&record.ConfidenceScore,
			&status,
			&parentHash,
			&record.CreatedAt,
			&record.CommittedAt,
			&record.DeprecatedAt,
			&taskStatus,
		); err != nil {
			return nil, MemoryProjectionPageCursor{},
				fmt.Errorf("scan memory projection page: %w", err)
		}
		record.MemoryType = memory.MemoryType(memoryType)
		record.Status = memory.MemoryStatus(status)
		record.TaskStatus = memory.TaskStatus(taskStatus)
		if parentHash != nil {
			record.ParentHash = *parentHash
		}
		records = append(records, &record)
		next = MemoryProjectionPageCursor{
			CreatedAt: record.CreatedAt.UTC().Format(time.RFC3339Nano),
			MemoryID:  record.MemoryID,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, MemoryProjectionPageCursor{},
			fmt.Errorf("walk memory projection page: %w", err)
	}
	return records, next, nil
}
