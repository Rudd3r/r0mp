package r0mp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVolumes(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()

	tests := []struct {
		name      string
		volumes   []string
		hasChroot bool
		wantErr   bool
		validate  func(t *testing.T, shares []interface{})
	}{
		{
			name:      "valid volume without chroot",
			volumes:   []string{tmpDir + ":/data"},
			hasChroot: false,
			wantErr:   false,
			validate: func(t *testing.T, shares []interface{}) {
				require.Equal(t, 1, len(shares), "should have 1 share(s)")
				// We'll validate the structure after parsing
			},
		},
		{
			name:      "valid volume with chroot",
			volumes:   []string{tmpDir + ":/data"},
			hasChroot: true,
			wantErr:   false,
			validate: func(t *testing.T, shares []interface{}) {
				require.Equal(t, 1, len(shares), "should have 1 share(s)")
			},
		},
		{
			name:      "valid read-only volume",
			volumes:   []string{tmpDir + ":/data:ro"},
			hasChroot: false,
			wantErr:   false,
			validate: func(t *testing.T, shares []interface{}) {
				require.Equal(t, 1, len(shares), "should have 1 share(s)")
			},
		},
		{
			name:      "multiple volumes",
			volumes:   []string{tmpDir + ":/data", tmpDir + ":/data2:ro"},
			hasChroot: true,
			wantErr:   false,
			validate: func(t *testing.T, shares []interface{}) {
				require.Equal(t, 2, len(shares), "should have 2 share(s)")
			},
		},
		{
			name:      "invalid format - missing guest path",
			volumes:   []string{tmpDir},
			hasChroot: false,
			wantErr:   true,
		},
		{
			name:      "invalid format - too many parts",
			volumes:   []string{tmpDir + ":/data:ro:extra"},
			hasChroot: false,
			wantErr:   true,
		},
		{
			name:      "invalid option",
			volumes:   []string{tmpDir + ":/data:rw"},
			hasChroot: false,
			wantErr:   true,
		},
		{
			name:      "non-absolute host path",
			volumes:   []string{"relative/path:/data"},
			hasChroot: false,
			wantErr:   true,
		},
		{
			name:      "non-absolute guest path",
			volumes:   []string{tmpDir + ":relative/path"},
			hasChroot: false,
			wantErr:   true,
		},
		{
			name:      "non-existent host path",
			volumes:   []string{"/nonexistent/path:/data"},
			hasChroot: false,
			wantErr:   true,
		},
	}

	// Create a temporary file for testing file vs directory
	tmpFile, err := os.CreateTemp(tmpDir, "testfile")
	require.NoError(t, err, "failed to create temp file")
	_ = tmpFile.Close()

	tests = append(tests, struct {
		name      string
		volumes   []string
		hasChroot bool
		wantErr   bool
		validate  func(t *testing.T, shares []interface{})
	}{
		name:      "host path is file not directory",
		volumes:   []string{tmpFile.Name() + ":/data"},
		hasChroot: false,
		wantErr:   true,
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shares, err := parseVolumes(tt.volumes, tt.hasChroot)
			if tt.wantErr {
				assert.Error(t, err, "parseVolumes() should return error")
			} else {
				require.NoError(t, err, "parseVolumes() should not return error")
			}
			if tt.wantErr {
				return
			}
			if !tt.wantErr && tt.validate != nil {
				// Convert to []interface{} for validation
				sharesInterface := make([]interface{}, len(shares))
				for i, s := range shares {
					sharesInterface[i] = s
				}
				tt.validate(t, sharesInterface)
			}
		})
	}
}

func TestParseVolumesChroot(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("mount point without chroot", func(t *testing.T) {
		shares, err := parseVolumes([]string{tmpDir + ":/data"}, false)
		require.NoError(t, err, "unexpected error")
		require.Equal(t, 1, len(shares), "should have 1 share(s)")

		expected := "/data"
		if shares[0].MountPoint != expected {
			t.Errorf("expected mount point %s, got %s", expected, shares[0].MountPoint)
		}
	})

	t.Run("mount point with chroot", func(t *testing.T) {
		shares, err := parseVolumes([]string{tmpDir + ":/data"}, true)
		require.NoError(t, err, "unexpected error")
		require.Equal(t, 1, len(shares), "should have 1 share(s)")

		expected := filepath.Join("/mnt/rootfs", "/data")
		if shares[0].MountPoint != expected {
			t.Errorf("expected mount point %s, got %s", expected, shares[0].MountPoint)
		}
	})
}

func TestParseVolumesReadOnly(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("read-write volume", func(t *testing.T) {
		shares, err := parseVolumes([]string{tmpDir + ":/data"}, false)
		require.NoError(t, err, "unexpected error")
		require.Equal(t, 1, len(shares), "should have 1 share(s)")

		if shares[0].ReadOnly {
			t.Error("expected ReadOnly to be false")
		}
	})

	t.Run("read-only volume", func(t *testing.T) {
		shares, err := parseVolumes([]string{tmpDir + ":/data:ro"}, false)
		require.NoError(t, err, "unexpected error")
		require.Equal(t, 1, len(shares), "should have 1 share(s)")

		if !shares[0].ReadOnly {
			t.Error("expected ReadOnly to be true")
		}
	})
}

func TestParseVolumesProperties(t *testing.T) {
	tmpDir := t.TempDir()

	shares, err := parseVolumes([]string{tmpDir + ":/data:ro", tmpDir + ":/data2"}, true)
	require.NoError(t, err, "unexpected error")
	require.Equal(t, 2, len(shares), "should have 2 share(s)")

	// Check first share
	if shares[0].HostPath != tmpDir {
		t.Errorf("expected host path %s, got %s", tmpDir, shares[0].HostPath)
	}
	if shares[0].MountTag != "vol0" {
		t.Errorf("expected mount tag vol0, got %s", shares[0].MountTag)
	}
	if !shares[0].ReadOnly {
		t.Error("expected first share to be read-only")
	}
	if shares[0].SecurityModel != "mapped-xattr" {
		t.Errorf("expected security model mapped-xattr, got %s", shares[0].SecurityModel)
	}

	// Check second share
	if shares[1].HostPath != tmpDir {
		t.Errorf("expected host path %s, got %s", tmpDir, shares[1].HostPath)
	}
	if shares[1].MountTag != "vol1" {
		t.Errorf("expected mount tag vol1, got %s", shares[1].MountTag)
	}
	if shares[1].ReadOnly {
		t.Error("expected second share to be read-write")
	}
}
