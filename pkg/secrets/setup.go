package secrets

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/term"
)

// configManager is an interface for managing configuration with insecure password storage
type configManager interface {
	Save() error
	SetInsecurePassword(password string)
	HasSecretStorePassword() bool
	SetSecretStorePassword(string)
}

// SetupSecretStorePassword guides the user through setting up their secret store password
func SetupSecretStorePassword(ctx context.Context, cfg configManager) error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Println("=== Secret Store Password Setup ===")
	fmt.Println()
	fmt.Println("The secret store requires a password to encrypt your secrets.")
	fmt.Println("You have several options for managing this password:")
	fmt.Println()
	fmt.Println("1. Use system keyring (recommended) - Securely store password in your system's keyring")
	fmt.Println("2. Use environment variable - Set R0MP_SECRET_STORE_PASSWORD in your environment")
	fmt.Println("3. Store in config (insecure) - Store a random password in the config file")
	fmt.Println()

	keyringAvailable := IsKeyringAvailable()
	if !keyringAvailable {
		fmt.Println("⚠️  Warning: System keyring is not available on this system.")
		fmt.Println("   You can only use options 2 or 3.")
		fmt.Println()
	}

	var choice string
	for {
		if keyringAvailable {
			fmt.Print("Which option would you like to use? (1/2/3): ")
		} else {
			fmt.Print("Which option would you like to use? (2/3): ")
		}

		choice, _ = reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		if keyringAvailable && (choice == "1" || choice == "2" || choice == "3") {
			break
		}
		if !keyringAvailable && (choice == "2" || choice == "3") {
			break
		}
		fmt.Println("Invalid choice. Please try again.")
		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}

	switch choice {
	case "1":
		return setupKeyring()
	case "2":
		return setupEnvironmentVariable()
	default:
		return setupInsecureConfig(cfg)
	}
}

func setupKeyring() error {
	fmt.Println()
	fmt.Println("=== Keyring Setup ===")
	fmt.Println()
	fmt.Println("Please enter a password for your secret store.")
	fmt.Println("This password will be securely stored in your system's keyring.")
	fmt.Println()

	password, err := promptPassword("Enter password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	confirmPassword, err := promptPassword("Confirm password: ")
	if err != nil {
		return fmt.Errorf("failed to read confirmation password: %w", err)
	}

	if password != confirmPassword {
		return fmt.Errorf("passwords do not match")
	}

	if err = SetSecretStorePasswordInKeyring(password); err != nil {
		return fmt.Errorf("failed to store password in keyring: %w", err)
	}

	fmt.Println()
	fmt.Println("✅ Password stored successfully in keyring!")
	fmt.Println()

	return nil
}

func setupEnvironmentVariable() error {
	fmt.Println()
	fmt.Println("=== Environment Variable Setup ===")
	fmt.Println()
	fmt.Println("You chose to use an environment variable.")
	fmt.Println()
	fmt.Println("Please set the R0MP_SECRET_STORE_PASSWORD environment variable:")
	fmt.Println()
	fmt.Println("  export R0MP_SECRET_STORE_PASSWORD=\"your-password-here\"")
	fmt.Println()
	fmt.Println("Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.) to make it permanent.")
	fmt.Println()

	password, err := promptPassword("Enter password to use now: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	fmt.Println()
	fmt.Println("✅ Using provided password for this session.")
	fmt.Println("   Remember to set the environment variable for future sessions!")
	fmt.Println()

	return nil
}

func setupInsecureConfig(cfg configManager) error {
	fmt.Println()
	fmt.Println("=== Insecure Config Setup ===")
	fmt.Println()
	fmt.Println("⚠️  WARNING: This option stores the password in plain text in the config file.")
	fmt.Println("   This is INSECURE and should only be used for testing or non-sensitive data.")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Are you sure you want to continue? (yes/no): ")
	confirmation, _ := reader.ReadString('\n')
	confirmation = strings.TrimSpace(strings.ToLower(confirmation))

	if confirmation != "yes" && confirmation != "y" {
		return fmt.Errorf("setup cancelled by user")
	}

	password := uuid.New().String()
	fmt.Println()
	fmt.Println("A random password has been generated.")

	if cfg != nil {
		cfg.SetInsecurePassword(password)
		if err := cfg.Save(); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
		fmt.Println("✅ Password saved to config file.")
	} else {
		fmt.Println("To use this option, add the following to your config file:")
		fmt.Println()
		fmt.Printf("  \"InsecureSecretStorePassword\": \"%s\"\n", password)
	}

	fmt.Println()
	fmt.Println("✅ Using generated password for this session.")
	fmt.Println()

	return nil
}

func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		reader := bufio.NewReader(os.Stdin)
		password, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(password), nil
	}

	passwordBytes, err := term.ReadPassword(fd)
	if err != nil {
		return "", err
	}
	fmt.Println()

	return string(passwordBytes), nil
}
