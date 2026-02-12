package image

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestReporter_ImageStart(t *testing.T) {
	var captured Event
	reporter := NewReporter(func(e Event) {
		captured = e
	})

	reporter.ImageStart(5)

	if captured.Type != EventImageStart {
		t.Errorf("Expected EventImageStart, got %v", captured.Type)
	}
	if captured.TotalLayers != 5 {
		t.Errorf("Expected 5 layers, got %d", captured.TotalLayers)
	}
}

func TestReporter_LayerStart(t *testing.T) {
	var captured Event
	reporter := NewReporter(func(e Event) {
		captured = e
	})

	digest := v1.Hash{Algorithm: "sha256", Hex: "abc123"}
	reporter.LayerStart(digest, 2, 5, 1024)

	if captured.Type != EventLayerStart {
		t.Errorf("Expected EventLayerStart, got %v", captured.Type)
	}
	if captured.LayerIndex != 2 {
		t.Errorf("Expected index 2, got %d", captured.LayerIndex)
	}
	if captured.TotalLayers != 5 {
		t.Errorf("Expected 5 total layers, got %d", captured.TotalLayers)
	}
	if captured.TotalBytes != 1024 {
		t.Errorf("Expected 1024 bytes, got %d", captured.TotalBytes)
	}
}

func TestReporter_CacheHit(t *testing.T) {
	var captured Event
	reporter := NewReporter(func(e Event) {
		captured = e
	})

	digest := v1.Hash{Algorithm: "sha256", Hex: "cached123"}
	reporter.CacheHit(digest, 0, 3)

	if captured.Type != EventCacheHit {
		t.Errorf("Expected EventCacheHit, got %v", captured.Type)
	}
	if !captured.CacheHit {
		t.Error("Expected CacheHit to be true")
	}
}

func TestReporter_Error(t *testing.T) {
	var captured Event
	reporter := NewReporter(func(e Event) {
		captured = e
	})

	testErr := errors.New("test error")
	reporter.Error(testErr, "operation failed")

	if captured.Type != EventError {
		t.Errorf("Expected EventError, got %v", captured.Type)
	}
	if captured.Error != testErr {
		t.Errorf("Expected error %v, got %v", testErr, captured.Error)
	}
	if captured.Message != "operation failed" {
		t.Errorf("Expected message 'operation failed', got %q", captured.Message)
	}
}

func TestNoOpReporter(t *testing.T) {
	reporter := NoOpReporter()

	// Should not panic
	reporter.ImageStart(10)
	reporter.LayerStart(v1.Hash{}, 0, 10, 1000)
	reporter.LayerComplete(v1.Hash{}, 0, 10)
	reporter.Error(errors.New("test"), "test")
	reporter.ImageComplete()
}

func TestProgressReader(t *testing.T) {
	data := bytes.Repeat([]byte("test"), 1000) // 4KB
	reader := bytes.NewReader(data)

	collector := NewCollector()
	digest := v1.Hash{Algorithm: "sha256", Hex: "test123"}

	pr := NewProgressReader(reader, collector.Reporter(), digest, 0, 1, int64(len(data)))

	// Read all data with delays to trigger progress reporting
	buf := make([]byte, 512)
	for {
		n, err := pr.Read(buf)
		if n > 0 {
			// Small delay to ensure progress reports trigger
			time.Sleep(110 * time.Millisecond)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
	}

	// Check events
	events := collector.Events()
	if len(events) == 0 {
		t.Fatal("Expected progress events, got none")
	}

	// Should have progress events
	hasProgress := false
	for _, e := range events {
		if e.Type == EventLayerProgress {
			hasProgress = true
			if e.LayerIndex != 0 {
				t.Errorf("Expected layer index 0, got %d", e.LayerIndex)
			}
			if e.TotalLayers != 1 {
				t.Errorf("Expected 1 total layer, got %d", e.TotalLayers)
			}
		}
	}
	if !hasProgress {
		t.Error("Expected at least one progress event")
	}
}

func TestCollector(t *testing.T) {
	collector := NewCollector()
	reporter := collector.Reporter()

	// Send various events
	reporter.ImageStart(3)
	reporter.LayerStart(v1.Hash{Hex: "abc"}, 0, 3, 1000)
	reporter.LayerComplete(v1.Hash{Hex: "abc"}, 0, 3)
	reporter.CacheHit(v1.Hash{Hex: "def"}, 1, 3)
	reporter.LayerStart(v1.Hash{Hex: "ghi"}, 2, 3, 2000)
	reporter.LayerComplete(v1.Hash{Hex: "ghi"}, 2, 3)
	reporter.ImageComplete()

	events := collector.Events()
	if len(events) != 7 {
		t.Errorf("Expected 7 events, got %d", len(events))
	}

	// Check stats
	stats := collector.Stats()
	if stats.LayersStarted != 2 {
		t.Errorf("Expected 2 layers started, got %d", stats.LayersStarted)
	}
	if stats.LayersCompleted != 2 {
		t.Errorf("Expected 2 layers completed, got %d", stats.LayersCompleted)
	}
	if stats.CacheHits != 1 {
		t.Errorf("Expected 1 cache hit, got %d", stats.CacheHits)
	}
	if stats.Duration == 0 {
		t.Error("Expected non-zero duration")
	}

	// Test clear
	collector.Clear()
	if len(collector.Events()) != 0 {
		t.Error("Expected empty events after clear")
	}
}

func TestEventType_String(t *testing.T) {
	tests := []struct {
		eventType EventType
		expected  string
	}{
		{EventLayerStart, "LayerStart"},
		{EventLayerProgress, "LayerProgress"},
		{EventLayerComplete, "LayerComplete"},
		{EventCacheHit, "CacheHit"},
		{EventError, "Error"},
		{EventImageStart, "ImageStart"},
		{EventImageComplete, "ImageComplete"},
	}

	for _, tt := range tests {
		got := tt.eventType.String()
		if got != tt.expected {
			t.Errorf("EventType.String() = %q, want %q", got, tt.expected)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		got := formatBytes(tt.bytes)
		if got != tt.expected {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, got, tt.expected)
		}
	}
}

func TestShortDigest(t *testing.T) {
	tests := []struct {
		digest   v1.Hash
		expected string
	}{
		{
			v1.Hash{Hex: "abcdefghijklmnopqrstuvwxyz"},
			"abcdefghijkl",
		},
		{
			v1.Hash{Hex: "short"},
			"short",
		},
	}

	for _, tt := range tests {
		got := shortDigest(tt.digest)
		if got != tt.expected {
			t.Errorf("shortDigest() = %q, want %q", got, tt.expected)
		}
	}
}

func TestSimpleConsoleReporter(t *testing.T) {
	// Just verify it doesn't panic
	log := slog.Default()
	reporter := SimpleConsoleReporter(log)

	digest := v1.Hash{Algorithm: "sha256", Hex: "test123"}
	reporter.ImageStart(2)
	reporter.LayerStart(digest, 0, 2, 1000)
	reporter.CacheHit(digest, 1, 2)
	reporter.ImageComplete()
}

func TestDetailedConsoleReporter(t *testing.T) {
	// Just verify it doesn't panic and produces output
	log := slog.Default()
	reporter := DetailedConsoleReporter(log)

	digest := v1.Hash{Algorithm: "sha256", Hex: "test123456789"}
	reporter.ImageStart(2)
	reporter.LayerStart(digest, 0, 2, 1000)

	// Brief sleep to ensure elapsed time is non-zero
	time.Sleep(10 * time.Millisecond)

	reporter.Report(Event{
		Type:        EventLayerProgress,
		LayerDigest: digest,
		LayerIndex:  0,
		TotalLayers: 2,
		BytesRead:   500,
		TotalBytes:  1000,
	})

	reporter.LayerComplete(digest, 0, 2)
	reporter.CacheHit(digest, 1, 2)
	reporter.ImageComplete()
	reporter.Error(errors.New("test error"), "test message")
}

func TestProgressReader_ReadPattern(t *testing.T) {
	data := []byte("hello world")
	reader := bytes.NewReader(data)

	collector := NewCollector()
	digest := v1.Hash{Algorithm: "sha256", Hex: "test"}

	pr := NewProgressReader(reader, collector.Reporter(), digest, 0, 1, int64(len(data)))

	// Read in small chunks with delays
	result := make([]byte, 0, len(data))
	buf := make([]byte, 3)
	for {
		n, err := pr.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
			time.Sleep(110 * time.Millisecond) // Trigger progress reporting
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
	}

	// Verify data integrity
	if !bytes.Equal(data, result) {
		t.Errorf("Data mismatch: expected %q, got %q", data, result)
	}

	// Verify some progress was reported
	events := collector.Events()
	if len(events) == 0 {
		t.Error("Expected progress events")
	}
}

func TestCollector_Stats_WithErrors(t *testing.T) {
	collector := NewCollector()
	reporter := collector.Reporter()

	reporter.ImageStart(1)
	reporter.LayerStart(v1.Hash{}, 0, 1, 100)
	reporter.Error(errors.New("test error"), "download failed")
	reporter.Error(errors.New("another error"), "extraction failed")
	reporter.ImageComplete()

	stats := collector.Stats()
	if stats.Errors != 2 {
		t.Errorf("Expected 2 errors, got %d", stats.Errors)
	}
}

func TestReporter_SetTotalBytes(t *testing.T) {
	reporter := NewReporter(nil)

	reporter.SetTotalBytes(12345)

	if reporter.totalBytes != 12345 {
		t.Errorf("Expected totalBytes 12345, got %d", reporter.totalBytes)
	}
}

func TestProgressReader_LargeData(t *testing.T) {
	// Create data and read in chunks with delays
	data := bytes.Repeat([]byte("x"), 10000)
	reader := bytes.NewReader(data)

	collector := NewCollector()
	digest := v1.Hash{Algorithm: "sha256", Hex: "large"}

	pr := NewProgressReader(reader, collector.Reporter(), digest, 0, 1, int64(len(data)))

	// Read in chunks with delays to trigger progress
	buf := make([]byte, 1000)
	for {
		n, err := pr.Read(buf)
		if n > 0 {
			time.Sleep(110 * time.Millisecond)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
	}

	// Should have multiple progress events
	events := collector.Events()
	progressCount := 0
	for _, e := range events {
		if e.Type == EventLayerProgress {
			progressCount++
			// Verify progress increases
			if e.BytesRead <= 0 || e.BytesRead > e.TotalBytes {
				t.Errorf("Invalid progress: %d/%d bytes", e.BytesRead, e.TotalBytes)
			}
		}
	}

	if progressCount == 0 {
		t.Error("Expected multiple progress events for large data")
	}
}

func BenchmarkProgressReader(b *testing.B) {
	data := bytes.Repeat([]byte("benchmark"), 10000)

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		pr := NewProgressReader(reader, NoOpReporter(), v1.Hash{}, 0, 1, int64(len(data)))
		_, _ = io.Copy(io.Discard, pr)
	}
}

func TestEventTimestamp(t *testing.T) {
	before := time.Now()

	var captured Event
	reporter := NewReporter(func(e Event) {
		captured = e
	})

	reporter.ImageStart(1)

	after := time.Now()

	if captured.Timestamp.Before(before) || captured.Timestamp.After(after) {
		t.Error("Event timestamp not in expected range")
	}
}

func TestMultipleReporters(t *testing.T) {
	collector1 := NewCollector()
	collector2 := NewCollector()

	// Create a reporter that sends to both collectors
	reporter := NewReporter(func(e Event) {
		collector1.Reporter().Report(e)
		collector2.Reporter().Report(e)
	})

	reporter.ImageStart(1)
	reporter.ImageComplete()

	if len(collector1.Events()) != len(collector2.Events()) {
		t.Error("Expected both collectors to have same event count")
	}
}
