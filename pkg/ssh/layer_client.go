package ssh

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"golang.org/x/crypto/ssh"
)

// LayerClient sends layers to guest via SSH subsystem
type LayerClient struct {
	client *ssh.Client
	log    *slog.Logger
}

// NewLayerClient creates a layer client
func NewLayerClient(client *ssh.Client, log *slog.Logger) *LayerClient {
	return &LayerClient{
		client: client,
		log:    log,
	}
}

// WriteLayer streams a layer to guest and extracts it
func (c *LayerClient) WriteLayer(target string, layerDigest string, reader io.Reader, size int64, final bool) error {
	c.log.Info("writing layer", "target", target, "layer", layerDigest, "size", size)

	session, err := c.client.NewSession()
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	defer func() { _ = session.Close() }()

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("get stdin: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("get stdout: %w", err)
	}

	if err := session.RequestSubsystem("layer-writer"); err != nil {
		return fmt.Errorf("request subsystem: %w", err)
	}

	req := LayerWriteRequest{
		Target: target,
		Layer:  layerDigest,
		Size:   size,
		Final:  final,
	}

	if err := json.NewEncoder(stdin).Encode(&req); err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	written, err := io.Copy(stdin, io.LimitReader(reader, size))
	if err != nil {
		return fmt.Errorf("stream layer: %w", err)
	}

	if written != size {
		return fmt.Errorf("size mismatch: wrote %d, expected %d", written, size)
	}

	_ = stdin.Close()
	c.log.Info("streamed layer", "bytes", written)

	var resp LayerWriteResponse
	if err := json.NewDecoder(stdout).Decode(&resp); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("extraction failed: %s", resp.Error)
	}

	c.log.Info("layer extracted", "files", resp.FilesExtracted, "bytes", resp.BytesReceived)
	return nil
}
