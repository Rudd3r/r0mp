package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func main() {
	// Get the program name (basename of argv[0])
	progName := filepath.Base(os.Args[0])

	// Dispatch to the appropriate utility based on how we were called
	switch progName {
	case "echo":
		cmdEcho(os.Args[1:])
	case "cat":
		cmdCat(os.Args[1:])
	case "ls":
		cmdLs(os.Args[1:])
	case "id":
		cmdId(os.Args[1:])
	case "pwd":
		cmdPwd(os.Args[1:])
	case "env":
		cmdEnv(os.Args[1:])
	case "grep":
		cmdGrep(os.Args[1:])
	case "sh":
		cmdSh(os.Args[1:])
	default:
		// If called directly as testutil, check first argument
		if len(os.Args) > 1 {
			switch os.Args[1] {
			case "echo":
				cmdEcho(os.Args[2:])
			case "cat":
				cmdCat(os.Args[2:])
			case "ls":
				cmdLs(os.Args[2:])
			case "id":
				cmdId(os.Args[2:])
			case "pwd":
				cmdPwd(os.Args[2:])
			case "env":
				cmdEnv(os.Args[2:])
			case "grep":
				cmdGrep(os.Args[2:])
			case "sh":
				cmdSh(os.Args[2:])
			default:
				_, _ = fmt.Fprintf(os.Stderr, "testutil: unknown command: %s\n", os.Args[1])
				os.Exit(1)
			}
		} else {
			_, _ = fmt.Fprint(os.Stderr, "Usage: testutil <command> [args...]\n")
			_, _ = fmt.Fprint(os.Stderr, "Available commands: echo, cat, ls, id, pwd, env, grep, sh\n")
			os.Exit(1)
		}
	}
}

func cmdEcho(args []string) {
	fmt.Println(strings.Join(args, " "))
}

func cmdCat(args []string) {
	if len(args) == 0 {
		// Read from stdin
		_, _ = io.Copy(os.Stdout, os.Stdin)
		return
	}

	for _, filename := range args {
		f, err := os.Open(filename)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "cat: %s: %v\n", filename, err)
			os.Exit(1)
		}
		_, _ = io.Copy(os.Stdout, f)
		_ = f.Close()
	}
}

func cmdLs(args []string) {
	var paths []string
	longFormat := false

	// Simple flag parsing
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			if strings.Contains(arg, "l") {
				longFormat = true
			}
			// -a flag for showing all files is noted but not needed
			// in this simplified ls implementation
		} else {
			paths = append(paths, arg)
		}
	}

	if len(paths) == 0 {
		paths = []string{"."}
	}

	for _, path := range paths {
		entries, err := os.ReadDir(path)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "ls: %s: %v\n", path, err)
			os.Exit(1)
		}

		for _, entry := range entries {
			if longFormat {
				info, err := entry.Info()
				if err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "ls: %s: %v\n", entry.Name(), err)
					continue
				}

				mode := info.Mode()
				modeStr := formatMode(mode)

				var uid, gid int
				if stat, ok := info.Sys().(*syscall.Stat_t); ok {
					uid = int(stat.Uid)
					gid = int(stat.Gid)
				}

				nlink := 1
				if stat, ok := info.Sys().(*syscall.Stat_t); ok {
					nlink = int(stat.Nlink)
				}

				fmt.Printf("%s %4d %-8d %-8d %8d %s %s\n",
					modeStr,
					nlink,
					uid,
					gid,
					info.Size(),
					info.ModTime().Format("Jan  2 15:04"),
					info.Name())
			} else {
				fmt.Println(entry.Name())
			}
		}
	}
}

func formatMode(mode os.FileMode) string {
	buf := make([]byte, 10)

	// File type
	switch {
	case mode&os.ModeDir != 0:
		buf[0] = 'd'
	case mode&os.ModeSymlink != 0:
		buf[0] = 'l'
	default:
		buf[0] = '-'
	}

	// Owner permissions
	buf[1] = permChar(mode, 0400, 'r')
	buf[2] = permChar(mode, 0200, 'w')
	buf[3] = permChar(mode, 0100, 'x')

	// Group permissions
	buf[4] = permChar(mode, 0040, 'r')
	buf[5] = permChar(mode, 0020, 'w')
	buf[6] = permChar(mode, 0010, 'x')

	// Other permissions
	buf[7] = permChar(mode, 0004, 'r')
	buf[8] = permChar(mode, 0002, 'w')
	buf[9] = permChar(mode, 0001, 'x')

	return string(buf)
}

func permChar(mode os.FileMode, mask os.FileMode, char byte) byte {
	if mode&mask != 0 {
		return char
	}
	return '-'
}

func cmdId(args []string) {
	uid := os.Getuid()
	gid := os.Getgid()
	euid := os.Geteuid()
	egid := os.Getegid()

	// Try to read /etc/passwd to get username
	username := getUserName(uid)
	groupname := getGroupName(gid)

	if username != "" {
		fmt.Printf("uid=%d(%s)", uid, username)
	} else {
		fmt.Printf("uid=%d", uid)
	}

	if groupname != "" {
		fmt.Printf(" gid=%d(%s)", gid, groupname)
	} else {
		fmt.Printf(" gid=%d", gid)
	}

	if euid != uid {
		eusername := getUserName(euid)
		if eusername != "" {
			fmt.Printf(" euid=%d(%s)", euid, eusername)
		} else {
			fmt.Printf(" euid=%d", euid)
		}
	}

	if egid != gid {
		egroupname := getGroupName(egid)
		if egroupname != "" {
			fmt.Printf(" egid=%d(%s)", egid, egroupname)
		} else {
			fmt.Printf(" egid=%d", egid)
		}
	}

	fmt.Println()
}

func getUserName(uid int) string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 3 {
			var id int
			_, _ = fmt.Sscanf(fields[2], "%d", &id)
			if id == uid {
				return fields[0]
			}
		}
	}
	return ""
}

func getGroupName(gid int) string {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		// If /etc/group doesn't exist, try to use /etc/passwd for primary group
		data, err = os.ReadFile("/etc/passwd")
		if err != nil {
			return ""
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}
			fields := strings.Split(line, ":")
			if len(fields) >= 4 {
				var id int
				_, _ = fmt.Sscanf(fields[3], "%d", &id)
				if id == gid {
					// Use username as group name
					return fields[0]
				}
			}
		}
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) >= 3 {
			var id int
			_, _ = fmt.Sscanf(fields[2], "%d", &id)
			if id == gid {
				return fields[0]
			}
		}
	}
	return ""
}

func cmdPwd(args []string) {
	pwd, err := os.Getwd()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "pwd: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(pwd)
}

func cmdEnv(args []string) {
	for _, envVar := range os.Environ() {
		fmt.Println(envVar)
	}
}

func cmdGrep(args []string) {
	if len(args) == 0 {
		_, _ = fmt.Fprint(os.Stderr, "grep: missing pattern\n")
		os.Exit(1)
	}

	pattern := args[0]
	found := false

	// Read all from stdin
	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "grep: %v\n", err)
		os.Exit(1)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.Contains(line, pattern) {
			fmt.Println(line)
			found = true
		}
	}

	if !found {
		os.Exit(1)
	}
}

func cmdSh(args []string) {
	// Very basic shell implementation for -c flag
	if len(args) < 2 || args[0] != "-c" {
		_, _ = fmt.Fprint(os.Stderr, "sh: only -c flag is supported\n")
		os.Exit(1)
	}

	// Parse the command string
	cmdStr := args[1]

	// Split commands by && operator (execute all if all succeed)
	commands := strings.Split(cmdStr, "&&")

	for _, cmd := range commands {
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}

		// Handle || operator (execute second if first fails)
		orParts := strings.Split(cmd, "||")

		for i, orCmd := range orParts {
			orCmd = strings.TrimSpace(orCmd)
			if orCmd == "" {
				continue
			}

			// Check if this command has a pipe
			if strings.Contains(orCmd, "|") {
				exitCode := executePipeline(orCmd)
				if exitCode == 0 {
					break // Success, no need to try other OR parts
				}
				// If this fails and there are more OR parts, continue
				if i == len(orParts)-1 {
					// Last OR part failed
					os.Exit(exitCode)
				}
			} else {
				// No pipe, execute normally
				exitCode := executeCommand(orCmd)
				if exitCode == 0 {
					break // Success, no need to try other OR parts
				}
				// If this fails and there are more OR parts, continue
				if i == len(orParts)-1 {
					// Last OR part failed
					os.Exit(exitCode)
				}
			}
		}
	}
}

func executePipeline(cmdStr string) int {
	pipeCommands := strings.Split(cmdStr, "|")

	var prevOutput []byte

	for i, pipeCmd := range pipeCommands {
		pipeCmd = strings.TrimSpace(pipeCmd)
		parts := strings.Fields(pipeCmd)
		if len(parts) == 0 {
			continue
		}

		// Handle environment variable expansion
		for j, part := range parts {
			if strings.HasPrefix(part, "$") {
				envVar := strings.TrimPrefix(part, "$")
				parts[j] = os.Getenv(envVar)
			}
		}

		// Save current stdin/stdout
		oldStdin := os.Stdin
		oldStdout := os.Stdout

		// If not first command, redirect stdin from previous output
		if i > 0 {
			r, w, _ := os.Pipe()
			os.Stdin = r
			go func() {
				_, _ = w.Write(prevOutput)
				_ = w.Close()
			}()
		}

		// If not last command, capture stdout
		if i < len(pipeCommands)-1 {
			r, w, _ := os.Pipe()
			defer func() {
				_ = r.Close()
				_ = w.Close()
			}()
			os.Stdout = w

			// Execute command
			exitCode := executeCommandParts(parts)

			_ = w.Close()
			prevOutput, _ = io.ReadAll(r)

			// Restore stdout
			os.Stdout = oldStdout
			os.Stdin = oldStdin

			if exitCode != 0 {
				return exitCode
			}
		} else {
			// Last command, let it write to real stdout
			exitCode := executeCommandParts(parts)

			// Restore stdin
			os.Stdin = oldStdin

			return exitCode
		}
	}

	return 0
}

func executeCommand(cmdStr string) int {
	parts := strings.Fields(cmdStr)
	if len(parts) == 0 {
		return 0
	}

	// Handle environment variable expansion
	for i, part := range parts {
		if strings.HasPrefix(part, "$") {
			envVar := strings.TrimPrefix(part, "$")
			parts[i] = os.Getenv(envVar)
		}
	}

	return executeCommandParts(parts)
}

func executeCommandParts(parts []string) int {
	// Use panic/recover to capture exit codes
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(int); ok {
				// This was an exit code, not a real panic
				return
			}
			// Re-panic if it's not an exit code
			panic(r)
		}
	}()

	switch parts[0] {
	case "echo":
		cmdEcho(parts[1:])
		return 0
	case "cat":
		return cmdCatForShell(parts[1:])
	case "ls":
		cmdLs(parts[1:])
		return 0
	case "id":
		cmdId(parts[1:])
		return 0
	case "pwd":
		cmdPwd(parts[1:])
		return 0
	case "env":
		cmdEnv(parts[1:])
		return 0
	case "grep":
		return cmdGrepForShell(parts[1:])
	default:
		_, _ = fmt.Fprintf(os.Stderr, "sh: %s: command not found\n", parts[0])
		return 127
	}
}

// cmdCatForShell is a version of cmdCat that returns exit code instead of calling os.Exit
func cmdCatForShell(args []string) int {
	if len(args) == 0 {
		// Read from stdin
		_, _ = io.Copy(os.Stdout, os.Stdin)
		return 0
	}

	for _, filename := range args {
		f, err := os.Open(filename)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "cat: %s: %v\n", filename, err)
			return 1
		}
		_, _ = io.Copy(os.Stdout, f)
		_ = f.Close()
	}
	return 0
}

// cmdGrepForShell is a version of cmdGrep that returns exit code instead of calling os.Exit
func cmdGrepForShell(args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(os.Stderr, "grep: missing pattern\n")
		return 1
	}

	pattern := args[0]
	found := false

	// Read all from stdin
	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "grep: %v\n", err)
		return 1
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.Contains(line, pattern) {
			fmt.Println(line)
			found = true
		}
	}

	if !found {
		return 1
	}
	return 0
}
