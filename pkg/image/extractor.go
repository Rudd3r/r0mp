package image

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/Rudd3r/r0mp/pkg/domain"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Extractor extracts Docker/OCI image layers to a filesystem
type Extractor struct {
	fs      domain.Writer
	baseDir string
}

// NewExtractorWithFS creates a new image extractor with a custom filesystem.Writer
// This allows extraction to different backends (disk images, mock filesystems, etc.)
func NewExtractorWithFS(fs domain.Writer) *Extractor {
	return &Extractor{
		fs:      fs,
		baseDir: "/",
	}
}

// LayerExtractor provides a simple interface for extracting layers one at a time
type LayerExtractor struct{}

// Extract extracts all layers from an image to the target directory
// Layers are applied in order, with later layers overwriting earlier ones
// Whiteout files are processed to handle deletions
func (e *Extractor) Extract(img v1.Image) error {
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("failed to get image layers: %w", err)
	}

	for i, layer := range layers {
		digest, err := layer.Digest()
		if err != nil {
			return fmt.Errorf("failed to get layer %d digest: %w", i, err)
		}

		if err := e.extractLayer(layer); err != nil {
			return fmt.Errorf("failed to extract layer %d (%s): %w", i, digest, err)
		}
	}

	return nil
}

// extractLayer extracts a single layer to the target directory
func (e *Extractor) extractLayer(layer v1.Layer) error {
	rc, err := layer.Compressed()
	if err != nil {
		return fmt.Errorf("failed to get layer reader: %w", err)
	}
	defer func() { _ = rc.Close() }()

	gzr, err := gzip.NewReader(rc)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}
		if err := e.extractEntry(header, tr); err != nil {
			return fmt.Errorf("failed to extract %s: %w", header.Name, err)
		}
	}

	return nil
}

// ExtractFromReader extracts a single layer from a compressed tar.gz stream.
// This method is useful when working with raw layer data (e.g., from network streams)
// rather than v1.Layer objects. The reader should provide gzip-compressed tar data.
// Returns the number of files extracted.
func (e *Extractor) ExtractFromReader(reader io.Reader) (int, error) {
	gzr, err := gzip.NewReader(reader)
	if err != nil {
		return 0, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)
	filesExtracted := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return filesExtracted, fmt.Errorf("failed to read tar header: %w", err)
		}
		if err := e.extractEntry(header, tr); err != nil {
			return filesExtracted, fmt.Errorf("failed to extract %s: %w", header.Name, err)
		}
		filesExtracted++
	}

	return filesExtracted, nil
}

// extractEntry extracts a single tar entry (file, directory, symlink, etc.)
func (e *Extractor) extractEntry(header *tar.Header, reader io.Reader) error {
	name := header.Name
	name = strings.TrimPrefix(name, "./")
	if name == "" {
		return nil // Skip empty entries
	}

	// Check if this is a whiteout file first (before path traversal check)
	// Whiteout files like .wh..wh..opq contain .. in their names which is legitimate
	if IsWhiteout(name) {
		return ProcessWhiteout(e.fs, e.baseDir, name)
	}

	// Security check: prevent path traversal attacks
	// Check for .. in path components (not in filenames)
	parts := strings.Split(name, string(filepath.Separator))
	for _, part := range parts {
		if part == ".." {
			return fmt.Errorf("invalid path (contains ..): %s", name)
		}
	}

	targetPath := filepath.Join(e.baseDir, name)
	switch header.Typeflag {
	case tar.TypeDir:
		return e.extractDirectory(targetPath, header)
	case tar.TypeReg:
		return e.extractFile(targetPath, header, reader)
	case tar.TypeSymlink:
		return e.extractSymlink(targetPath, header)
	case tar.TypeLink:
		return e.extractHardlink(targetPath, header)
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		// Device files and FIFOs - skip for now as they require special privileges
		// In a real implementation for root filesystems, these would need proper handling
		return nil
	default:
		// Unknown type - skip
		return nil
	}
}

// extractXattrs extracts extended attributes from PAX records
// Docker images store extended attributes using the SCHILY.xattr.* prefix
func extractXattrs(header *tar.Header) map[string][]byte {
	if len(header.PAXRecords) == 0 {
		return nil
	}

	const xattrPrefix = "SCHILY.xattr."
	xattrs := make(map[string][]byte)
	for key, value := range header.PAXRecords {
		if strings.HasPrefix(key, xattrPrefix) {
			xattrs[key[len(xattrPrefix):]] = []byte(value)
		}
	}
	if len(xattrs) == 0 {
		return nil
	}
	return xattrs
}

// extractDirectory creates a directory with appropriate permissions
func (e *Extractor) extractDirectory(path string, header *tar.Header) error {
	return e.fs.MkdirAll(path, domain.FileInfo{
		FName:        path,
		FMode:        fs.FileMode(header.Mode),
		Uid:          uint32(header.Uid),
		Gid:          uint32(header.Gid),
		AccessTime:   header.AccessTime,
		ChangeTime:   header.ChangeTime,
		ModifiedTime: header.ModTime,
		CreateTime:   header.ModTime,
		Xattrs:       extractXattrs(header),
	})
}

// extractFile extracts a regular file
func (e *Extractor) extractFile(path string, header *tar.Header, reader io.Reader) error {
	return e.fs.WriteFile(path, domain.FileInfo{
		FName:        header.Name,
		FSize:        header.Size,
		FMode:        fs.FileMode(header.Mode),
		Uid:          uint32(header.Uid),
		Gid:          uint32(header.Gid),
		AccessTime:   header.AccessTime,
		ChangeTime:   header.ChangeTime,
		ModifiedTime: header.ModTime,
		CreateTime:   header.ModTime,
		Xattrs:       extractXattrs(header),
	}, reader)
}

// extractSymlink creates a symbolic link
func (e *Extractor) extractSymlink(path string, header *tar.Header) error {
	return e.fs.Symlink(header.Linkname, path, domain.FileInfo{
		FName:        header.Name,
		FSize:        header.Size,
		FMode:        fs.FileMode(header.Mode),
		Uid:          uint32(header.Uid),
		Gid:          uint32(header.Gid),
		AccessTime:   header.AccessTime,
		ChangeTime:   header.ChangeTime,
		ModifiedTime: header.ModTime,
		CreateTime:   header.ModTime,
		Xattrs:       extractXattrs(header),
	})
}

// extractHardlink creates a hard link
func (e *Extractor) extractHardlink(path string, header *tar.Header) error {
	linkTarget := filepath.Join(e.baseDir, header.Linkname)
	return e.fs.Link(linkTarget, path)
}
