package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Rudd3r/r0mp/pkg/raftinit"
)

func main() {

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	})).With("name", "raftinit")
	log.Info("Starting raft init")

	var exit int
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		os.Exit(exit)
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		slog.Info("Received interrupt signal, shutting down...")
		cancel()
	}()

	if err := raftinit.NewInit(ctx, log).Run(); err != nil {
		slog.Error(err.Error())
		exit = 1
	}
}
