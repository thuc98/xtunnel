package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"xtunnel/internal/config"
	"xtunnel/internal/connector"
	"xtunnel/internal/receiver"
)

func main() {
	serverMode := flag.Bool("s", false, "run as server")
	clientMode := flag.Bool("c", false, "run as client")
	configPath := flag.String("f", "./config.yaml", "config file path")
	flag.Parse()

	if *serverMode == *clientMode {
		fmt.Fprintln(os.Stderr, "exactly one of -s or -c is required")
		os.Exit(2)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *serverMode {
		c, createErr := connector.NewQuicConnector(cfg.Server)
		if createErr != nil {
			log.Fatal(createErr)
		}
		err = c.Serve(ctx)
	} else {
		r, createErr := receiver.NewQuicReceiver(cfg.Client, cfg.Routes, cfg.ReverseRoutes)
		if createErr != nil {
			log.Fatal(createErr)
		}
		err = r.Start(ctx)
	}
	if err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}
