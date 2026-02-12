package domain

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func ParseSizeBytes(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("empty size string")
	}

	re := regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*([kmgtpe]i?b?)?$`)
	matches := re.FindStringSubmatch(s)
	if matches == nil {
		return 0, fmt.Errorf("invalid size format: %q", s)
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %w", err)
	}

	unit := matches[2]
	var multiplier int64 = 1

	// Use binary (IEC) units by default (1024-based)
	switch {
	case strings.HasPrefix(unit, "k"):
		multiplier = 1 << 10 // 1 KiB
	case strings.HasPrefix(unit, "m"):
		multiplier = 1 << 20 // 1 MiB
	case strings.HasPrefix(unit, "g"):
		multiplier = 1 << 30 // 1 GiB
	case strings.HasPrefix(unit, "t"):
		multiplier = 1 << 40 // 1 TiB
	case strings.HasPrefix(unit, "p"):
		multiplier = 1 << 50 // 1 PiB
	case strings.HasPrefix(unit, "e"):
		multiplier = 1 << 60 // 1 EiB
	}

	return int64(value * float64(multiplier)), nil
}

func FormatSizeBytes(bytes int64) string {
	if bytes < 0 {
		return "-" + FormatSizeBytes(-bytes)
	}

	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%db", bytes)
	}

	units := []string{"k", "m", "g", "t", "p", "e"}
	value := float64(bytes)
	i := -1

	for value >= unit && i < len(units)-1 {
		value /= unit
		i++
	}

	// Use integer display if it's a whole number
	if value == float64(int64(value)) {
		return fmt.Sprintf("%d%s", int64(value), units[i])
	}

	return fmt.Sprintf("%.1f%s", value, units[i])
}

func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		minutes := int(d.Minutes())
		seconds := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	if d < 24*time.Hour {
		hours := int(d.Hours())
		minutes := int(d.Minutes()) % 60
		return fmt.Sprintf("%dh%dm", hours, minutes)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd%dh", days, hours)
}

func FormatStatus(state string, started, stopped time.Time) string {
	switch state {
	case RaftStateRunning:
		if !started.IsZero() {
			duration := time.Since(started)
			return fmt.Sprintf("Running %s", FormatDuration(duration))
		}
		return "Running"
	case RaftStateStopped:
		if !stopped.IsZero() {
			duration := time.Since(stopped)
			return fmt.Sprintf("Stopped %s ago", FormatDuration(duration))
		}
		return "Stopped"
	case RaftStateCreated:
		return "Created"
	case RaftStateStarting:
		return "Starting"
	case RaftStateReady:
		return "Ready"
	default:
		return state
	}
}
