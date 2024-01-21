package service

import (
	"database/sql"
	"log/slog"

	"github.com/coreos/go-iptables/iptables"
	"github.com/labstack/echo/v4"
)

type (
	Service struct {
		*echo.Echo
		*iptables.IPTables
		*sql.DB
		iptablesDBTable string
		*slog.Logger
	}
	Option func(*Service) error
)

func New(opts ...Option) (*Service, error) {
	s := &Service{}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}

	return s, nil
}
