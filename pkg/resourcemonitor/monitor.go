package resourcemonitor

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Monitor struct {
	ctx      context.Context
	log      *slog.Logger
	interval time.Duration
	lastCPU  *cpuStats
	lastNet  map[string]*netStats
	mu       sync.RWMutex
	current  *ResourceStats
}

type cpuStats struct {
	user    uint64
	nice    uint64
	system  uint64
	idle    uint64
	iowait  uint64
	irq     uint64
	softirq uint64
	steal   uint64
}

type ResourceStats struct {
	Timestamp time.Time       `json:"timestamp"`
	CPU       *CPUStats       `json:"cpu,omitempty"`
	Memory    *MemStats       `json:"memory,omitempty"`
	Disks     []DiskStats     `json:"disks,omitempty"`
	Network   []NetworkStats  `json:"network,omitempty"`
	Processes []ProcessStats  `json:"processes,omitempty"`
}

type CPUStats struct {
	UsagePercent float64 `json:"usage_percent"`
}

type MemStats struct {
	TotalMB     uint64  `json:"total_mb"`
	UsedMB      uint64  `json:"used_mb"`
	FreeMB      uint64  `json:"free_mb"`
	AvailableMB uint64  `json:"available_mb"`
	CachedMB    uint64  `json:"cached_mb"`
	UsagePercent float64 `json:"usage_percent"`
}

type DiskStats struct {
	MountPoint   string  `json:"mountpoint"`
	TotalMB      uint64  `json:"total_mb"`
	UsedMB       uint64  `json:"used_mb"`
	AvailableMB  uint64  `json:"available_mb"`
	UsagePercent float64 `json:"usage_percent"`
}

type NetworkStats struct {
	Interface string `json:"interface"`
	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
}

type ProcessStats struct {
	PID         int     `json:"pid"`
	Name        string  `json:"name"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemoryMB    uint64  `json:"memory_mb"`
	Threads     int     `json:"threads"`
}

type memStats struct {
	total     uint64
	free      uint64
	available uint64
	buffers   uint64
	cached    uint64
	used      uint64
}

type netStats struct {
	rxBytes   uint64
	rxPackets uint64
	txBytes   uint64
	txPackets uint64
}

type diskStats struct {
	mountPoint string
	total      uint64
	used       uint64
	available  uint64
}

type processStats struct {
	pid     int
	name    string
	cpu     float64
	memory  uint64
	threads int
}

func NewMonitor(ctx context.Context, log *slog.Logger, interval time.Duration) *Monitor {
	return &Monitor{
		ctx:      ctx,
		log:      log,
		interval: interval,
		lastNet:  make(map[string]*netStats),
		current:  &ResourceStats{},
	}
}

func (rm *Monitor) Start() error {
	rm.log.Info("starting resource monitor", "interval", rm.interval)

	ticker := time.NewTicker(rm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-rm.ctx.Done():
			rm.log.Info("resource monitor stopped")
			return rm.ctx.Err()
		case <-ticker.C:
			rm.collectStats()
		}
	}
}

func (rm *Monitor) GetStats() ResourceStats {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return *rm.current
}

func (rm *Monitor) collectStats() {
	stats := &ResourceStats{
		Timestamp: time.Now(),
	}

	cpu := rm.getCPUUtilization()
	if cpu >= 0 {
		stats.CPU = &CPUStats{
			UsagePercent: cpu,
		}
	}

	mem := rm.getMemoryStats()
	if mem != nil {
		stats.Memory = &MemStats{
			TotalMB:      mem.total / 1024 / 1024,
			UsedMB:       mem.used / 1024 / 1024,
			FreeMB:       mem.free / 1024 / 1024,
			AvailableMB:  mem.available / 1024 / 1024,
			CachedMB:     mem.cached / 1024 / 1024,
			UsagePercent: float64(mem.used) * 100 / float64(mem.total),
		}
	}

	disks := rm.getDiskStats()
	for _, disk := range disks {
		stats.Disks = append(stats.Disks, DiskStats{
			MountPoint:   disk.mountPoint,
			TotalMB:      disk.total / 1024 / 1024,
			UsedMB:       disk.used / 1024 / 1024,
			AvailableMB:  disk.available / 1024 / 1024,
			UsagePercent: float64(disk.used) * 100 / float64(disk.total),
		})
	}

	net := rm.getNetworkStats()
	for iface, netStat := range net {
		stats.Network = append(stats.Network, NetworkStats{
			Interface: iface,
			RxBytes:   netStat.rxBytes,
			RxPackets: netStat.rxPackets,
			TxBytes:   netStat.txBytes,
			TxPackets: netStat.txPackets,
		})
	}

	processes := rm.getTopProcesses(5)
	for _, proc := range processes {
		stats.Processes = append(stats.Processes, ProcessStats{
			PID:        proc.pid,
			Name:       proc.name,
			CPUPercent: proc.cpu,
			MemoryMB:   proc.memory / 1024 / 1024,
			Threads:    proc.threads,
		})
	}

	rm.mu.Lock()
	rm.current = stats
	rm.mu.Unlock()
}

func (rm *Monitor) getCPUUtilization() float64 {
	file, err := os.Open("/proc/stat")
	if err != nil {
		rm.log.Error("failed to read cpu stats", "error", err)
		return -1
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return -1
	}

	line := scanner.Text()
	if !strings.HasPrefix(line, "cpu ") {
		return -1
	}

	fields := strings.Fields(line)
	if len(fields) < 8 {
		return -1
	}

	current := &cpuStats{
		user:    parseUint64(fields[1]),
		nice:    parseUint64(fields[2]),
		system:  parseUint64(fields[3]),
		idle:    parseUint64(fields[4]),
		iowait:  parseUint64(fields[5]),
		irq:     parseUint64(fields[6]),
		softirq: parseUint64(fields[7]),
	}
	if len(fields) > 8 {
		current.steal = parseUint64(fields[8])
	}

	if rm.lastCPU == nil {
		rm.lastCPU = current
		return -1
	}

	idle := current.idle - rm.lastCPU.idle
	total := (current.user - rm.lastCPU.user) +
		(current.nice - rm.lastCPU.nice) +
		(current.system - rm.lastCPU.system) +
		idle +
		(current.iowait - rm.lastCPU.iowait) +
		(current.irq - rm.lastCPU.irq) +
		(current.softirq - rm.lastCPU.softirq) +
		(current.steal - rm.lastCPU.steal)

	rm.lastCPU = current

	if total == 0 {
		return 0
	}

	return float64(total-idle) * 100.0 / float64(total)
}

func (rm *Monitor) getMemoryStats() *memStats {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		rm.log.Error("failed to read memory stats", "error", err)
		return nil
	}
	defer func() { _ = file.Close() }()

	stats := &memStats{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.TrimSuffix(fields[0], ":")
		value := parseUint64(fields[1]) * 1024

		switch key {
		case "MemTotal":
			stats.total = value
		case "MemFree":
			stats.free = value
		case "MemAvailable":
			stats.available = value
		case "Buffers":
			stats.buffers = value
		case "Cached":
			stats.cached = value
		}
	}

	stats.used = stats.total - stats.free - stats.buffers - stats.cached
	return stats
}

func (rm *Monitor) getDiskStats() []diskStats {
	var stats []diskStats

	file, err := os.Open("/proc/mounts")
	if err != nil {
		rm.log.Error("failed to read mounts", "error", err)
		return stats
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		device := fields[0]
		mountPoint := fields[1]
		fsType := fields[2]

		if !strings.HasPrefix(device, "/dev/") || seen[mountPoint] {
			continue
		}

		if fsType == "tmpfs" || fsType == "devtmpfs" || fsType == "proc" || fsType == "sysfs" {
			continue
		}

		seen[mountPoint] = true

		var statfs syscall.Statfs_t
		if err := syscall.Statfs(mountPoint, &statfs); err != nil {
			continue
		}

		total := statfs.Blocks * uint64(statfs.Bsize)
		available := statfs.Bavail * uint64(statfs.Bsize)
		used := total - (statfs.Bfree * uint64(statfs.Bsize))

		stats = append(stats, diskStats{
			mountPoint: mountPoint,
			total:      total,
			used:       used,
			available:  available,
		})
	}

	return stats
}

func (rm *Monitor) getNetworkStats() map[string]*netStats {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		rm.log.Error("failed to read network stats", "error", err)
		return nil
	}
	defer func() { _ = file.Close() }()

	current := make(map[string]*netStats)
	scanner := bufio.NewScanner(file)

	scanner.Scan()
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}

		iface := strings.TrimSpace(parts[0])
		if iface == "lo" {
			continue
		}

		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}

		stats := &netStats{
			rxBytes:   parseUint64(fields[0]),
			rxPackets: parseUint64(fields[1]),
			txBytes:   parseUint64(fields[8]),
			txPackets: parseUint64(fields[9]),
		}

		if last, ok := rm.lastNet[iface]; ok {
			stats.rxBytes -= last.rxBytes
			stats.rxPackets -= last.rxPackets
			stats.txBytes -= last.txBytes
			stats.txPackets -= last.txPackets
		}

		current[iface] = stats
	}

	rm.lastNet = make(map[string]*netStats)
	for k, v := range current {
		rm.lastNet[k] = &netStats{
			rxBytes:   v.rxBytes,
			rxPackets: v.rxPackets,
			txBytes:   v.txBytes,
			txPackets: v.txPackets,
		}
	}

	return current
}

func (rm *Monitor) getTopProcesses(limit int) []processStats {
	var processes []processStats

	dir, err := os.Open("/proc")
	if err != nil {
		rm.log.Error("failed to open /proc", "error", err)
		return processes
	}
	defer func() { _ = dir.Close() }()

	entries, err := dir.Readdirnames(-1)
	if err != nil {
		rm.log.Error("failed to read /proc", "error", err)
		return processes
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		if stats := rm.getProcessStats(pid); stats != nil {
			processes = append(processes, *stats)
		}
	}

	for i := 0; i < len(processes)-1; i++ {
		for j := i + 1; j < len(processes); j++ {
			if processes[j].cpu > processes[i].cpu {
				processes[i], processes[j] = processes[j], processes[i]
			}
		}
	}

	if len(processes) > limit {
		processes = processes[:limit]
	}

	return processes
}

func (rm *Monitor) getProcessStats(pid int) *processStats {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return nil
	}

	line := string(data)
	endComm := strings.LastIndex(line, ")")
	if endComm == -1 {
		return nil
	}

	startComm := strings.Index(line, "(")
	if startComm == -1 {
		return nil
	}
	name := line[startComm+1 : endComm]

	fields := strings.Fields(line[endComm+2:])
	if len(fields) < 20 {
		return nil
	}

	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	statusData, err := os.ReadFile(statusPath)
	if err != nil {
		return nil
	}

	var memory uint64
	var threads int
	statusLines := strings.Split(string(statusData), "\n")
	for _, line := range statusLines {
		if strings.HasPrefix(line, "VmRSS:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				memory = parseUint64(parts[1]) * 1024
			}
		} else if strings.HasPrefix(line, "Threads:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				threads = int(parseUint64(parts[1]))
			}
		}
	}

	return &processStats{
		pid:     pid,
		name:    name,
		cpu:     0,
		memory:  memory,
		threads: threads,
	}
}

func parseUint64(s string) uint64 {
	val, _ := strconv.ParseUint(s, 10, 64)
	return val
}
