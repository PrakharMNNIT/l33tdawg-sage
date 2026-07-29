package store

import (
	"context"
	"fmt"
	"strings"
)

func (s *SQLiteStore) sqliteTableHasColumn(
	ctx context.Context, table, column string,
) (bool, error) {
	rows, err := s.conn.QueryContext(ctx, `PRAGMA table_info("`+
		strings.ReplaceAll(table, `"`, `""`)+`")`)
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// addSQLiteColumnIfMissing tolerates only the exact concurrent duplicate
// column race and then verifies that another process installed the column.
func (s *SQLiteStore) addSQLiteColumnIfMissing(
	ctx context.Context, table, column, statement string,
) error {
	exists, err := s.sqliteTableHasColumn(ctx, table, column)
	if err != nil {
		return fmt.Errorf("inspect %s.%s: %w", table, column, err)
	}
	if exists {
		return nil
	}
	if _, err := s.writeExecContext(ctx, statement); err != nil {
		duplicate := strings.Contains(strings.ToLower(err.Error()),
			"duplicate column name: "+strings.ToLower(column))
		if !duplicate {
			return fmt.Errorf("add %s.%s: %w", table, column, err)
		}
		exists, inspectErr := s.sqliteTableHasColumn(ctx, table, column)
		if inspectErr != nil || !exists {
			return fmt.Errorf("verify concurrently added %s.%s: %w", table, column, err)
		}
	}
	return nil
}
