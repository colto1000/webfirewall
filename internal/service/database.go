package service

import (
	"database/sql"
	"fmt"
)

func NewDatabaseConn(username, password, url, port, database string) (*sql.DB, error) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", username, password, url, port, database))
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

func WithDatabaseConn(username, password, url, port, database string) Option {
	// log.Println("\n\n ***", username, password, url, port, database)
	return func(s *Service) error {
		db, err := NewDatabaseConn(username, password, url, port, database)
		if err != nil {
			return err
		}

		s.DB = db

		return nil
	}
}
