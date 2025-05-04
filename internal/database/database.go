package database

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Database interface {
	InsertToken(ctx context.Context, guid int) (int, error)
	StoreRefresh(ctx context.Context, id int, hash string) error
	GetRefresh(ctx context.Context, id int) (hash, status string, err error)
	MarkRefreshUsed(ctx context.Context, id int) error
	InvalidateAllRefreshForGUID(ctx context.Context, guid int) error
}

type DBPool interface {
	Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
}

type PGXDatabase struct {
	pool DBPool
}

func NewPGXDatabase(pool DBPool) *PGXDatabase {
	return &PGXDatabase{pool: pool}
}

func (db *PGXDatabase) InsertToken(ctx context.Context, guid int) (int, error) {
	var id int
	err := db.pool.QueryRow(ctx,
		"INSERT INTO tokens(guid, refresh_hash, status) VALUES($1, '', 'unused') RETURNING id",
		guid,
	).Scan(&id)
	return id, err
}

func (db *PGXDatabase) StoreRefresh(ctx context.Context, id int, hash string) error {
	_, err := db.pool.Exec(ctx,
		"UPDATE tokens SET refresh_hash=$1, status='unused' WHERE id=$2",
		hash, id,
	)
	return err
}

func (db *PGXDatabase) GetRefresh(ctx context.Context, id int) (string, string, error) {
	var hash, status string
	err := db.pool.QueryRow(ctx,
		"SELECT refresh_hash, status FROM tokens WHERE id=$1",
		id,
	).Scan(&hash, &status)
	return hash, status, err
}

func (db *PGXDatabase) MarkRefreshUsed(ctx context.Context, id int) error {
	_, err := db.pool.Exec(ctx,
		"UPDATE tokens SET status='used' WHERE id=$1",
		id,
	)
	return err
}

func (db *PGXDatabase) InvalidateAllRefreshForGUID(ctx context.Context, guid int) error {
	_, err := db.pool.Exec(ctx,
		"UPDATE tokens SET status='blocked' WHERE guid=$1",
		guid,
	)
	return err
}
