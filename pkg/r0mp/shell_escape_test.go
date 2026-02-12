package r0mp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShellEscape(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple string",
			input:    "hello",
			expected: "'hello'",
		},
		{
			name:     "string with spaces",
			input:    "hello world",
			expected: "'hello world'",
		},
		{
			name:     "string with single quote",
			input:    "it's",
			expected: "'it'\\''s'",
		},
		{
			name:     "string with special chars",
			input:    "echo $VAR",
			expected: "'echo $VAR'",
		},
		{
			name:     "command flag",
			input:    "-c",
			expected: "'-c'",
		},
		{
			name:     "complex command",
			input:    "date +%Y-%m-%d",
			expected: "'date +%Y-%m-%d'",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "''",
		},
		{
			name:     "string with quotes and spaces",
			input:    "hello 'world'",
			expected: "'hello '\\''world'\\'''",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shellEscape(tt.input)
			assert.Equal(t, tt.expected, result, "shellEscape(%q) should match expected value", tt.input)
		})
	}
}

func TestShellEscapeDockerExecStyle(t *testing.T) {
	// Simulate what happens when user types: sandbox exec mybox /bin/sh -c "date"
	// After shell parsing, os.Args would be: ["sandbox", "exec", "mybox", "/bin/sh", "-c", "date"]

	tests := []struct {
		name     string
		command  string
		args     []string
		expected string
	}{
		{
			name:     "sh with -c flag",
			command:  "/bin/sh",
			args:     []string{"-c", "date"},
			expected: "'/bin/sh' '-c' 'date'",
		},
		{
			name:     "sh with -c and complex command",
			command:  "/bin/sh",
			args:     []string{"-c", "echo 'hello world'"},
			expected: "'/bin/sh' '-c' 'echo '\\''hello world'\\'''",
		},
		{
			name:     "command with equals sign",
			command:  "ls",
			args:     []string{"--time-style=long-iso"},
			expected: "'ls' '--time-style=long-iso'",
		},
		{
			name:     "command with multiple args",
			command:  "docker",
			args:     []string{"run", "-it", "--rm", "ubuntu", "bash"},
			expected: "'docker' 'run' '-it' '--rm' 'ubuntu' 'bash'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			escapedArgs := make([]string, 0, len(tt.args)+1)
			escapedArgs = append(escapedArgs, shellEscape(tt.command))
			for _, arg := range tt.args {
				escapedArgs = append(escapedArgs, shellEscape(arg))
			}
			result := strings.Join(escapedArgs, " ")
			assert.Equal(t, tt.expected, result, "escaped command should match expected value")
		})
	}
}
