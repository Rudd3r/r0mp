package assets

import (
	"bytes"
	"compress/gzip"
	"embed"
	"io"
)

//go:embed vmlinuz initrd.gz e2fsck mke2fs raftinit
var FS embed.FS

func Kernel() io.Reader {
	f, _ := FS.ReadFile("vmlinuz")
	return bytes.NewBuffer(f)
}

func Initrd() io.ReaderAt {
	f, _ := FS.Open("initrd.gz")
	defer func() { _ = f.Close() }()
	gz, _ := gzip.NewReader(f)
	defer func() { _ = gz.Close() }()
	decompressed, _ := io.ReadAll(gz)
	return bytes.NewReader(decompressed)
}

func E2fsck() []byte {
	f, _ := FS.ReadFile("e2fsck")
	return f
}

func Mke2fs() []byte {
	f, _ := FS.ReadFile("mke2fs")
	return f
}

func RaftInit() []byte {
	f, _ := FS.ReadFile("raftinit")
	return f
}
