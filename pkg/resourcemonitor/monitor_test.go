package resourcemonitor

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestMonitor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	monitor := NewMonitor(ctx, log, 1*time.Second)

	done := make(chan error)
	go func() {
		done <- monitor.Start()
	}()

	select {
	case err := <-done:
		if err != nil && err != context.DeadlineExceeded {
			t.Fatalf("monitor failed: %v", err)
		}
	case <-ctx.Done():
	}
}

func TestGetCPUUtilization(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	monitor := NewMonitor(context.Background(), log, 1*time.Second)

	cpu := monitor.getCPUUtilization()
	if cpu != -1 {
		t.Logf("First CPU reading: %.2f%% (expected -1)", cpu)
	}

	time.Sleep(100 * time.Millisecond)
	cpu = monitor.getCPUUtilization()
	if cpu >= 0 && cpu <= 100 {
		t.Logf("Second CPU reading: %.2f%%", cpu)
	}
}

func TestGetMemoryStats(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	monitor := NewMonitor(context.Background(), log, 1*time.Second)
	stats := monitor.getMemoryStats()

	if stats == nil {
		t.Fatal("failed to get memory stats")
	}

	if stats.total == 0 {
		t.Error("memory total is 0")
	}

	t.Logf("Memory: total=%dMB used=%dMB free=%dMB available=%dMB",
		stats.total/1024/1024,
		stats.used/1024/1024,
		stats.free/1024/1024,
		stats.available/1024/1024)
}

func TestGetDiskStats(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	monitor := NewMonitor(context.Background(), log, 1*time.Second)
	stats := monitor.getDiskStats()

	if len(stats) == 0 {
		t.Log("no disk stats available (may be expected in test environment)")
		return
	}

	for _, disk := range stats {
		t.Logf("Disk: mount=%s total=%dMB used=%dMB available=%dMB",
			disk.mountPoint,
			disk.total/1024/1024,
			disk.used/1024/1024,
			disk.available/1024/1024)
	}
}

func TestGetNetworkStats(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	monitor := NewMonitor(context.Background(), log, 1*time.Second)
	stats := monitor.getNetworkStats()

	if len(stats) == 0 {
		t.Log("no network stats available")
		return
	}

	for iface, netStat := range stats {
		t.Logf("Network: interface=%s rx_bytes=%d rx_packets=%d tx_bytes=%d tx_packets=%d",
			iface,
			netStat.rxBytes,
			netStat.rxPackets,
			netStat.txBytes,
			netStat.txPackets)
	}
}

func TestGetTopProcesses(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	monitor := NewMonitor(context.Background(), log, 1*time.Second)
	processes := monitor.getTopProcesses(5)

	if len(processes) == 0 {
		t.Fatal("no processes found")
	}

	for _, proc := range processes {
		t.Logf("Process: pid=%d name=%s memory=%dMB threads=%d",
			proc.pid,
			proc.name,
			proc.memory/1024/1024,
			proc.threads)
	}
}

func TestGetStats(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	monitor := NewMonitor(context.Background(), log, 1*time.Second)
	
	monitor.collectStats()
	time.Sleep(100 * time.Millisecond)
	
	stats := monitor.GetStats()
	
	if stats.Memory == nil {
		t.Error("expected memory stats")
	}
	
	t.Logf("Stats collected at: %v", stats.Timestamp)
	if stats.CPU != nil {
		t.Logf("CPU: %.2f%%", stats.CPU.UsagePercent)
	}
	if stats.Memory != nil {
		t.Logf("Memory: %dMB used / %dMB total", stats.Memory.UsedMB, stats.Memory.TotalMB)
	}
}
