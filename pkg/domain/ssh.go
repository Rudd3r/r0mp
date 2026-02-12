package domain

import (
	"io"

	"golang.org/x/crypto/ssh"
)

const (
	SSHManagementUser  = "raftinitmgt"
	SSHServerGuestPort = 22044

	GuestPrivateIP = "10.0.2.20"
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
