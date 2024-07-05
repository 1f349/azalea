package database

import (
	"context"
	"database/sql"
	"errors"
)

var ErrCannotConvertToTx = errors.New("cannot convert to tx")

func (q *Queries) Tx(ctx context.Context, opts *sql.TxOptions, fn func(db *Queries) error) error {
	db, ok := q.db.(*sql.DB)
	if !ok {
		return ErrCannotConvertToTx
	}
	tx, err := db.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	err = fn(q.WithTx(tx))
	if err != nil {
		return errors.Join(tx.Rollback(), err)
	}
	return tx.Commit()
}
