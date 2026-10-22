package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"xtunnel/internal/app"
	"xtunnel/internal/config"
	"xtunnel/internal/dashboard"
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

	a := app.New(*configPath, *serverMode)
	a.SetDashboard(dashboard.New(a))

	_ = a.Run(ctx, cfg)
}
