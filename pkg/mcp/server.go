package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/Rudd3r/r0mp/pkg/domain"
	sshpkg "github.com/Rudd3r/r0mp/pkg/ssh"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	Names        []string
	Host         string
	Port         string
	StdIO        bool
	AllowedRafts map[string]*domain.Raft
	Log          *slog.Logger
	CTX          context.Context
}

func (s *Server) Start() (err error) {

	mcpServer := server.NewMCPServer(
		domain.AppName,
		"1.0.0",
		server.WithToolCapabilities(false),
	)

	mcpServer.AddTool(
		mcp.Tool{
			Name:        "exec",
			Description: "Execute a command in a raft VM. Returns stdout and stderr output.",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]interface{}{
					"raft_name": map[string]interface{}{
						"type":        "string",
						"description": fmt.Sprintf("Name of the raft to execute in. Allowed: %v", s.Names),
					},
					"command": map[string]interface{}{
						"type":        "string",
						"description": "The command to execute",
					},
					"environment": map[string]interface{}{
						"type":        "object",
						"description": "Optional environment variables as key-value pairs",
						"additionalProperties": map[string]interface{}{
							"type": "string",
						},
					},
					"detach": map[string]interface{}{
						"type":        "boolean",
						"description": "Run command in detached mode (non-blocking)",
						"default":     false,
					},
				},
				Required: []string{"raft_name", "command"},
			},
		},
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			argsMap, ok := request.Params.Arguments.(map[string]interface{})
			if !ok {
				return mcp.NewToolResultError("arguments must be a map"), nil
			}

			raftName, ok := argsMap["raft_name"].(string)
			if !ok {
				return mcp.NewToolResultError("raft_name must be a string"), nil
			}

			command, ok := argsMap["command"].(string)
			if !ok {
				return mcp.NewToolResultError("command must be a string"), nil
			}

			raft, ok := s.AllowedRafts[raftName]
			if !ok {
				return mcp.NewToolResultError(fmt.Sprintf("raft %q is not allowed or not running", raftName)), nil
			}

			env := make(map[string]string)
			if envVal, ok := argsMap["environment"]; ok {
				if envMap, ok := envVal.(map[string]interface{}); ok {
					for k, v := range envMap {
						if vStr, ok := v.(string); ok {
							env[k] = vStr
						}
					}
				}
			}

			detach := false
			if detachVal, ok := argsMap["detach"]; ok {
				if detachBool, ok := detachVal.(bool); ok {
					detach = detachBool
				}
			}

			output, execErr := s.execInRaft(ctx, raft, command, env, detach)

			if execErr != nil {
				return mcp.NewToolResultError(fmt.Sprintf("execution failed: %v\nOutput:\n%s", execErr, output)), nil
			}

			return mcp.NewToolResultText(output), nil
		},
	)

	if s.StdIO {
		stdioServer := server.NewStdioServer(mcpServer)
		return stdioServer.Listen(s.CTX, os.Stdin, os.Stdout)
	}

	httpServer := server.NewStreamableHTTPServer(mcpServer)
	s.Log.Info("Starting MCP server", "address", fmt.Sprintf("%s:%s", s.Host, s.Port))
	return httpServer.Start(fmt.Sprintf("%s:%s", s.Host, s.Port))
}

// execInRaft executes a command in a raft via SSH and returns the combined output
func (s *Server) execInRaft(ctx context.Context, raft *domain.Raft, command string, environment map[string]string, detach bool) (string, error) {
	clientSSHKey, err := raft.GetSSHClientKey()
	if err != nil {
		return "", fmt.Errorf("getting ssh client key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(clientSSHKey)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	hostSSHKey, err := raft.GetSSHHostKey()
	if err != nil {
		return "", fmt.Errorf("getting ssh host key: %w", err)
	}

	hostKey, err := ssh.NewSignerFromKey(hostSSHKey)
	if err != nil {
		return "", fmt.Errorf("could not parse server ssh public key: %w", err)
	}

	env := raft.GetEnvironment()
	if raft.Image != "" {
		env[sshpkg.EnvRaftChroot] = "/mnt/rootfs"
		env[sshpkg.EnvRaftUser] = raft.User
	}
	for k, v := range environment {
		env[k] = v
	}

	var stdout, stderr strings.Builder
	clientConfig := &domain.SSHClientConfig{
		User:            domain.SSHManagementUser,
		Host:            "127.0.0.1",
		Port:            int(raft.SSHServerPort.HostPort),
		EnableTTY:       false, // Non-interactive
		Interactive:     false,
		Detach:          detach,
		EnvironmentVars: env,
		Command:         command,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
		Stderr:          &stderr,
		Stdout:          &stdout,
		Stdin:           nil,
	}

	err = sshpkg.Client(ctx, s.Log, clientConfig)

	output := stdout.String()
	if stderr.Len() > 0 {
		if len(output) > 0 {
			output += "\n--- stderr ---\n"
		}
		output += stderr.String()
	}

	if detach {
		if len(output) == 0 {
			output = "Command started in detached mode"
		}
	}

	return output, err
}
