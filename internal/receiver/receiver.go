package receiver

import (
	"context"

	"xtunnel/internal/config"
)

type Receiver interface {
	Start(context.Context) error
}

type Factory interface {
	New(config.ClientConfig, []config.RouteConfig, []config.ReverseRouteConfig) (Receiver, error)
}
