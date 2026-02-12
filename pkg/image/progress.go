package image

import (
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Event represents a progress event during image processing
type Event struct {
	Type        EventType
	LayerDigest v1.Hash
	LayerIndex  int
	TotalLayers int
	BytesRead   int64
	TotalBytes  int64
	CacheHit    bool
	Error       error
	Message     string
	Timestamp   time.Time
}

// EventType represents the type of progress event
type EventType int

const (
	// EventLayerStart indicates a layer download/extraction is starting
	EventLayerStart EventType = iota
	// EventLayerProgress indicates progress during layer processing
	EventLayerProgress
	// EventLayerComplete indicates a layer is complete
	EventLayerComplete
	// EventCacheHit indicates a layer was found in cache
	EventCacheHit
	// EventError indicates an error occurred
	EventError
	// EventImageStart indicates image processing is starting
	EventImageStart
	// EventImageComplete indicates image processing is complete
	EventImageComplete
)

func (t EventType) String() string {
	switch t {
	case EventLayerStart:
		return "LayerStart"
	case EventLayerProgress:
		return "LayerProgress"
	case EventLayerComplete:
		return "LayerComplete"
	case EventCacheHit:
		return "CacheHit"
	case EventError:
		return "Error"
	case EventImageStart:
		return "ImageStart"
	case EventImageComplete:
		return "ImageComplete"
	default:
		return "Unknown"
	}
}

// Reporter provides progress reporting functionality
type Reporter struct {
	callback   func(Event)
	totalBytes int64
	mu         sync.RWMutex
}

// NewReporter creates a new progress reporter with the given callback
func NewReporter(callback func(Event)) *Reporter {
	return &Reporter{
		callback: callback,
	}
}

// NoOpReporter returns a reporter that doesn't report anything
func NoOpReporter() *Reporter {
	return &Reporter{
		callback: func(Event) {},
	}
}

// SetTotalBytes sets the expected total bytes for progress calculation
func (r *Reporter) SetTotalBytes(bytes int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.totalBytes = bytes
}

// Report sends a progress event
func (r *Reporter) Report(event Event) {
	event.Timestamp = time.Now()

	r.mu.RLock()
	callback := r.callback
	r.mu.RUnlock()

	if callback != nil {
		callback(event)
	}
}

// ImageStart reports the start of image processing
func (r *Reporter) ImageStart(totalLayers int) {
	r.Report(Event{
		Type:        EventImageStart,
		TotalLayers: totalLayers,
	})
}

// ImageComplete reports completion of image processing
func (r *Reporter) ImageComplete() {
	r.Report(Event{
		Type: EventImageComplete,
	})
}

// LayerStart reports the start of a layer operation
func (r *Reporter) LayerStart(digest v1.Hash, index, total int, size int64) {
	r.Report(Event{
		Type:        EventLayerStart,
		LayerDigest: digest,
		LayerIndex:  index,
		TotalLayers: total,
		TotalBytes:  size,
	})
}

// LayerComplete reports completion of a layer operation
func (r *Reporter) LayerComplete(digest v1.Hash, index, total int) {
	r.Report(Event{
		Type:        EventLayerComplete,
		LayerDigest: digest,
		LayerIndex:  index,
		TotalLayers: total,
	})
}

// CacheHit reports a cache hit for a layer
func (r *Reporter) CacheHit(digest v1.Hash, index, total int) {
	r.Report(Event{
		Type:        EventCacheHit,
		LayerDigest: digest,
		LayerIndex:  index,
		TotalLayers: total,
		CacheHit:    true,
	})
}

// Error reports an error
func (r *Reporter) Error(err error, message string) {
	r.Report(Event{
		Type:    EventError,
		Error:   err,
		Message: message,
	})
}

// ProgressReader wraps an io.Reader to report read progress
type ProgressReader struct {
	reader     io.Reader
	reporter   *Reporter
	digest     v1.Hash
	index      int
	total      int
	totalSize  int64
	bytesRead  atomic.Int64
	lastReport time.Time
	reportMu   sync.Mutex
}

// NewProgressReader creates a new progress-reporting reader
func NewProgressReader(r io.Reader, reporter *Reporter, digest v1.Hash, index, total int, size int64) *ProgressReader {
	return &ProgressReader{
		reader:     r,
		reporter:   reporter,
		digest:     digest,
		index:      index,
		total:      total,
		totalSize:  size,
		lastReport: time.Now(),
	}
}

func (pr *ProgressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)

	if n > 0 {
		newTotal := pr.bytesRead.Add(int64(n))

		// Report progress every 100ms or when complete
		pr.reportMu.Lock()
		elapsed := time.Since(pr.lastReport)
		shouldReport := elapsed >= 100*time.Millisecond || err == io.EOF
		if shouldReport {
			pr.lastReport = time.Now()
		}
		pr.reportMu.Unlock()

		if shouldReport {
			pr.reporter.Report(Event{
				Type:        EventLayerProgress,
				LayerDigest: pr.digest,
				LayerIndex:  pr.index,
				TotalLayers: pr.total,
				BytesRead:   newTotal,
				TotalBytes:  pr.totalSize,
			})
		}
	}

	return n, err
}

// Close closes the underlying reader if it implements io.Closer
func (pr *ProgressReader) Close() error {
	if closer, ok := pr.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// SimpleConsoleReporter creates a reporter that logs using slog
func SimpleConsoleReporter(log *slog.Logger) *Reporter {
	return NewReporter(func(e Event) {
		switch e.Type {
		case EventImageStart:
			log.Info("processing image", "layers", e.TotalLayers)
		case EventLayerStart:
			log.Info("starting layer",
				"layer_index", e.LayerIndex+1,
				"total_layers", e.TotalLayers,
				"digest", e.LayerDigest)
		case EventCacheHit:
			log.Info("cache hit",
				"layer_index", e.LayerIndex+1,
				"total_layers", e.TotalLayers,
				"digest", e.LayerDigest)
		case EventLayerProgress:
			if e.TotalBytes > 0 {
				pct := float64(e.BytesRead) / float64(e.TotalBytes) * 100
				log.Info("layer progress",
					"layer_index", e.LayerIndex+1,
					"total_layers", e.TotalLayers,
					"percent", fmt.Sprintf("%.1f%%", pct),
					"bytes_read", e.BytesRead,
					"total_bytes", e.TotalBytes)
			} else {
				log.Info("layer progress",
					"layer_index", e.LayerIndex+1,
					"total_layers", e.TotalLayers,
					"bytes_read", e.BytesRead)
			}
		case EventLayerComplete:
			log.Info("completed layer",
				"layer_index", e.LayerIndex+1,
				"total_layers", e.TotalLayers,
				"digest", e.LayerDigest)
		case EventImageComplete:
			log.Info("image processing complete")
		case EventError:
			if e.Message != "" {
				log.Error("image processing error", "message", e.Message, "error", e.Error)
			} else {
				log.Error("image processing error", "error", e.Error)
			}
		}
	})
}

// DetailedConsoleReporter creates a reporter with more detailed output using slog
func DetailedConsoleReporter(log *slog.Logger) *Reporter {
	startTime := time.Now()

	return NewReporter(func(e Event) {
		elapsed := e.Timestamp.Sub(startTime)

		switch e.Type {
		case EventImageStart:
			log.Info("image processing started",
				"elapsed", elapsed,
				"layers_to_process", e.TotalLayers)
		case EventLayerStart:
			log.Info("layer starting download",
				"elapsed", elapsed,
				"layer_index", e.LayerIndex+1,
				"total_layers", e.TotalLayers,
				"digest_short", shortDigest(e.LayerDigest))
		case EventCacheHit:
			log.Info("layer cache hit",
				"elapsed", elapsed,
				"layer_index", e.LayerIndex+1,
				"total_layers", e.TotalLayers,
				"digest_short", shortDigest(e.LayerDigest))
		case EventLayerProgress:
			if e.TotalBytes > 0 {
				pct := float64(e.BytesRead) / float64(e.TotalBytes) * 100
				log.Info("layer progress",
					"elapsed", elapsed,
					"layer_index", e.LayerIndex+1,
					"total_layers", e.TotalLayers,
					"digest_short", shortDigest(e.LayerDigest),
					"percent", fmt.Sprintf("%.1f%%", pct),
					"bytes_read_formatted", formatBytes(e.BytesRead),
					"total_bytes_formatted", formatBytes(e.TotalBytes))
			}
		case EventLayerComplete:
			log.Info("layer complete",
				"elapsed", elapsed,
				"layer_index", e.LayerIndex+1,
				"total_layers", e.TotalLayers,
				"digest_short", shortDigest(e.LayerDigest))
		case EventImageComplete:
			log.Info("image processing complete",
				"elapsed", elapsed,
				"total_time_seconds", elapsed.Seconds())
		case EventError:
			if e.Message != "" {
				log.Error("image processing error",
					"elapsed", elapsed,
					"message", e.Message,
					"error", e.Error)
			} else {
				log.Error("image processing error",
					"elapsed", elapsed,
					"error", e.Error)
			}
		}
	})
}

// shortDigest returns a shortened version of the digest for display
func shortDigest(digest v1.Hash) string {
	hex := digest.Hex
	if len(hex) > 12 {
		return hex[:12]
	}
	return hex
}

// formatBytes formats byte counts in a human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Collector collects all events for later analysis
type Collector struct {
	mu     sync.RWMutex
	events []Event
}

// NewCollector creates a new event collector
func NewCollector() *Collector {
	return &Collector{
		events: make([]Event, 0),
	}
}

// Reporter returns a reporter that collects events
func (c *Collector) Reporter() *Reporter {
	return NewReporter(func(e Event) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.events = append(c.events, e)
	})
}

// Events returns all collected events
func (c *Collector) Events() []Event {
	c.mu.RLock()
	defer c.mu.RUnlock()

	events := make([]Event, len(c.events))
	copy(events, c.events)
	return events
}

// Clear clears all collected events
func (c *Collector) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = c.events[:0]
}

// Stats returns statistics about collected events
func (c *Collector) Stats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := Stats{}

	for _, e := range c.events {
		switch e.Type {
		case EventLayerStart:
			stats.LayersStarted++
		case EventLayerComplete:
			stats.LayersCompleted++
		case EventCacheHit:
			stats.CacheHits++
		case EventError:
			stats.Errors++
		}

		if e.Type == EventImageStart && e.Timestamp.After(stats.StartTime) {
			stats.StartTime = e.Timestamp
		}
		if e.Type == EventImageComplete && e.Timestamp.After(stats.EndTime) {
			stats.EndTime = e.Timestamp
		}
	}

	if !stats.EndTime.IsZero() && !stats.StartTime.IsZero() {
		stats.Duration = stats.EndTime.Sub(stats.StartTime)
	}

	return stats
}

// Stats contains statistics about progress events
type Stats struct {
	LayersStarted   int
	LayersCompleted int
	CacheHits       int
	Errors          int
	StartTime       time.Time
	EndTime         time.Time
	Duration        time.Duration
}
