package ssh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Rudd3r/r0mp/pkg/filesystem"
	"github.com/Rudd3r/r0mp/pkg/image"
	"golang.org/x/crypto/ssh"
)

// LayerWriteRequest is sent by host before streaming layer
type LayerWriteRequest struct {
	Target string `json:"target"`
	Layer  string `json:"layer"`
	Size   int64  `json:"size"`
	Final  bool   `json:"final"`
}

// LayerWriteResponse is sent after extraction
type LayerWriteResponse struct {
	Success        bool   `json:"success"`
	BytesReceived  int64  `json:"bytes_received,omitempty"`
	FilesExtracted int    `json:"files_extracted,omitempty"`
	Error          string `json:"error,omitempty"`
}

// handleLayerWriter handles the layer-writer subsystem
func (s *SSHServer) handleLayerWriter(channel ssh.Channel, user string) {
	defer func() { _ = channel.Close() }()

	s.log.Info("layer-writer subsystem started", "user", user)

	decoder := json.NewDecoder(channel)
	var req LayerWriteRequest
	if err := decoder.Decode(&req); err != nil {
		s.sendLayerResponse(channel, &LayerWriteResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid request: %v", err),
		})
		return
	}

	s.log.Info("layer write request",
		"target", req.Target,
		"layer", req.Layer,
		"size", req.Size)

	if !isValidTargetPath(req.Target) {
		s.sendLayerResponse(channel, &LayerWriteResponse{
			Success: false,
			Error:   "invalid target path",
		})
		return
	}

	// Create a MultiReader that first reads any buffered data from the JSON decoder,
	// then continues reading from the channel. This ensures we don't lose any bytes
	// that the decoder may have buffered while parsing JSON.
	buffered := decoder.Buffered()

	// Skip any trailing newline from JSON encoding
	// json.Encoder.Encode() adds a \n, and it may be in the buffered data
	firstByte := make([]byte, 1)
	var dataReader io.Reader
	if n, _ := buffered.Read(firstByte); n == 1 && firstByte[0] == '\n' {
		// Newline was present and consumed, continue with buffered + channel
		dataReader = io.MultiReader(buffered, channel)
	} else {
		// No newline or different byte, put it back and continue
		dataReader = io.MultiReader(bytes.NewReader(firstByte[:1]), buffered, channel)
	}

	filesExtracted, err := s.extractLayer(dataReader, req)
	if err != nil {
		s.sendLayerResponse(channel, &LayerWriteResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	if req.Final {
		s.notify(ServerEvent{
			Name: ServerEventFinalLayerWritten,
			Attributes: map[string]string{
				"target": req.Target,
			},
		})
	}

	s.sendLayerResponse(channel, &LayerWriteResponse{
		Success:        true,
		BytesReceived:  req.Size,
		FilesExtracted: filesExtracted,
	})
}

// extractLayer reads tar.gz from reader and extracts using the image.Extractor
func (s *SSHServer) extractLayer(reader io.Reader, req LayerWriteRequest) (int, error) {
	writer, err := filesystem.NewOSWriter(req.Target)
	if err != nil {
		return 0, fmt.Errorf("create writer: %w", err)
	}

	// Create an extractor with "/" as base since OSWriter already handles the target directory
	extractor := image.NewExtractorWithFS(writer)

	// Use the extractor to process the layer
	filesExtracted, err := extractor.ExtractFromReader(reader)
	if err != nil {
		return 0, fmt.Errorf("extract layer: %w", err)
	}

	s.log.Info("layer extracted", "files", filesExtracted)
	return filesExtracted, nil
}

func (s *SSHServer) sendLayerResponse(channel ssh.Channel, resp *LayerWriteResponse) {
	if err := json.NewEncoder(channel).Encode(resp); err != nil {
		s.log.Error("failed to send response", "error", err)
	}
}

func isValidTargetPath(path string) bool {
	return (strings.HasPrefix(path, "/mnt/") ||
		strings.HasPrefix(path, "/tmp/")) &&
		!strings.Contains(path, "..")
}
