package database

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Database interface {
	CreateTableQuery(ctx context.Context) error
	InsertTokenQuery(ctx context.Context) (int, error)
	UpdateTokenQuery(ctx context.Context, id int, refreshtoken string) error
	SetStatusTokenQuery(ctx context.Context, id int, status string) error
	SelectRefreshTokenQuery(ctx context.Context, id int) (string, string, error)
}

type DBPool interface {
	Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, arguments ...interface{}) pgx.Row
}

type PGXDatabase struct {
	pool DBPool
}

func NewPGXDatabase(pool DBPool) *PGXDatabase {
	return &PGXDatabase{pool: pool}
}

func (db *PGXDatabase) CreateTableQuery(ctx context.Context) error {
	_, err := db.pool.Exec(ctx, "CREATE TABLE IF NOT EXISTS tokens (id SERIAL PRIMARY KEY, refreshhash TEXT, status TEXT);")
	return err
}

func (db *PGXDatabase) InsertTokenQuery(ctx context.Context) (int, error) {
	var ID int
	err := db.pool.QueryRow(ctx, "INSERT INTO tokens(status) values($1) RETURNING id", "unused").Scan(&ID)
	return ID, err
}

func (db *PGXDatabase) UpdateTokenQuery(ctx context.Context, id int, refreshtoken string) error {
	_, err := db.pool.Exec(ctx, "UPDATE tokens SET refreshhash = $1 WHERE id = $2", refreshtoken, id)
	return err
}

func (db *PGXDatabase) SetStatusTokenQuery(ctx context.Context, id int, status string) error {
	_, err := db.pool.Exec(ctx, "UPDATE tokens SET status = $1 WHERE id = $2", status, id)
	return err
}

func (db *PGXDatabase) SelectRefreshTokenQuery(ctx context.Context, id int) (string, string, error) {
	refresh := ""
	status := ""
	err := db.pool.QueryRow(ctx, "SELECT refreshhash, status FROM tokens WHERE id = $1", id).Scan(&refresh, &status)
	return refresh, status, err
}
