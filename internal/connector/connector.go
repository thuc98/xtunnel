package connector

import (
	"context"

	"xtunnel/internal/config"
)

type Connector interface {
	Serve(context.Context) error
}

type Factory interface {
	New(config.ServerConfig) (Connector, error)
}
