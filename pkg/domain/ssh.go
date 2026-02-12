package domain

import (
	"io"

	"golang.org/x/crypto/ssh"
)

const (
	SSHManagementUser  = "raftinitmgt"
	SSHServerGuestPort = 22044
	GuestPrivateIP     = "10.0.2.20"

	EnvRaftChroot    = "RAFT_CHROOT"
	EnvRaftUser      = "RAFT_USER"
	EnvRaftDetach    = "RAFT_DETACH"
	EnvRaftLogOutput = "RAFT_LOG_OUTPUT"
)

type SSHClientConfig struct {
	User            string
	Host            string
	Port            int
	Command         string
	EnvironmentVars map[string]string
	EnableTTY       bool
	Interactive     bool
	Detach          bool
	LogOutput       bool // Log stdout/stderr using service logger when in detached mode
	Auth            []ssh.AuthMethod
	HostKeyCallback ssh.HostKeyCallback
	Stderr          io.Writer
	Stdout          io.Writer
	Stdin           io.Reader
}

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
