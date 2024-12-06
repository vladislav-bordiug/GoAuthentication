package database

import (
	"context"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCreateTableQuery(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	database := NewPGXDatabase(mock)
	defer mock.Close()
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tokens").
		WillReturnResult(pgxmock.NewResult("CREATE", 1))
	err = database.CreateTableQuery(context.Background())
	assert.NoError(t, err)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestInsertTokenQuery(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	database := NewPGXDatabase(mock)
	defer mock.Close()
	status := "unused"
	mock.ExpectQuery("INSERT INTO tokens").
		WithArgs(status).
		WillReturnRows(pgxmock.NewRows([]string{"id"}).AddRow(1))
	_, err = database.InsertTokenQuery(context.Background())
	assert.NoError(t, err)
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestUpdateTokenQuery(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	database := NewPGXDatabase(mock)
	defer mock.Close()
	refresh := "hash"
	id := 1
	mock.ExpectExec("UPDATE tokens SET").
		WithArgs(refresh, id).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	err = database.UpdateTokenQuery(context.Background(), id, refresh)
	assert.NoError(t, err)
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestSetStatusTokenQuery(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	database := NewPGXDatabase(mock)
	defer mock.Close()
	status := "used"
	id := 1
	mock.ExpectExec("UPDATE tokens SET").
		WithArgs(status, id).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	err = database.SetStatusTokenQuery(context.Background(), id, status)
	assert.NoError(t, err)
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestSelectRefreshTokenQuery(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	database := NewPGXDatabase(mock)
	defer mock.Close()
	id := 1
	mock.ExpectQuery("SELECT refreshhash, status FROM tokens").
		WithArgs(id).
		WillReturnRows(pgxmock.NewRows([]string{"refreshhash", "status"}).AddRow("hash", "unused"))
	_, _, err = database.SelectRefreshTokenQuery(context.Background(), id)
	assert.NoError(t, err)
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}
