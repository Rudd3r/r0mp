package resourcemonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type HTTPServer struct {
	monitor *Monitor
	server  *http.Server
	log     *slog.Logger
}

func NewHTTPServer(ctx context.Context, log *slog.Logger, addr string, monitor *Monitor) *HTTPServer {
	h := &HTTPServer{
		monitor: monitor,
		log:     log,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", h.handleMetrics)
	mux.HandleFunc("/health", h.handleHealth)

	h.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return h
}

func (h *HTTPServer) Start() error {
	h.log.Info("starting resource monitor HTTP server", "addr", h.server.Addr)
	
	if err := h.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("HTTP server error: %w", err)
	}
	return nil
}

func (h *HTTPServer) Stop(ctx context.Context) error {
	h.log.Info("stopping resource monitor HTTP server")
	return h.server.Shutdown(ctx)
}

func (h *HTTPServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.monitor.GetStats()
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		h.log.Error("failed to encode stats", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func (h *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.monitor.GetStats()
	
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"uptime":    time.Since(stats.Timestamp).Seconds(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	if err := json.NewEncoder(w).Encode(health); err != nil {
		h.log.Error("failed to encode health", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}
