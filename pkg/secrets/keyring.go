package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/google/uuid"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

const (
	// keyringSecretStorePassword is the key for the secret store password in the keyring
	keyringSecretStorePassword = domain.AppName + "_secret_store_password"
)

var (
	// keyringService is the service name used in the keyring
	// Can be overridden for testing to avoid interfering with production keyring
	keyringService = domain.AppName

	// ErrSecretNotFound is returned when a secret is not found in the keyring
	ErrSecretNotFound = errors.New("secret not found in keyring")
)

func setKeyringServiceForTesting(testServiceName string) func() {
	originalService := keyringService
	keyringService = testServiceName
	return func() {
		keyringService = originalService
	}
}

// GetSecretStorePasswordFromKeyring retrieves the secret store password from the keyring
func GetSecretStorePasswordFromKeyring() (string, error) {
	password, err := keyring.Get(keyringService, keyringSecretStorePassword)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrSecretNotFound
		}
		return "", fmt.Errorf("failed to get password from keyring: %w", err)
	}
	return password, nil
}

// SetSecretStorePasswordInKeyring stores the secret store password in the keyring
func SetSecretStorePasswordInKeyring(password string) error {
	if err := keyring.Set(keyringService, keyringSecretStorePassword, password); err != nil {
		return fmt.Errorf("failed to set password in keyring: %w", err)
	}
	return nil
}

// DeleteSecretStorePasswordFromKeyring removes the secret store password from the keyring
func DeleteSecretStorePasswordFromKeyring() error {
	if err := keyring.Delete(keyringService, keyringSecretStorePassword); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil // Already deleted, not an error
		}
		return fmt.Errorf("failed to delete password from keyring: %w", err)
	}
	return nil
}

// IsKeyringAvailable checks if the keyring is available on the system
func IsKeyringAvailable() bool {
	// Try to get a non-existent key to check if the keyring is available
	_, err := keyring.Get(keyringService, uuid.New().String())
	if errors.Is(err, keyring.ErrNotFound) {
		return true
	}
	// Check for specific error types that indicate the keyring is not available
	if err != nil && err.Error() != "" {
		// On systems without keyring support, we'll get an error
		// that's not ErrNotFound
		return false
	}
	return true
}

// EnsurePasswordFromConfig ensures a password is set in the config
func EnsurePasswordFromConfig(ctx context.Context, cfg configManager) error {
	if cfg.HasSecretStorePassword() {
		return nil
	}

	password, err := GetSecretStorePasswordFromKeyring()
	if err == nil && password != "" {
		cfg.SetSecretStorePassword(password)
		return nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		if errors.Is(err, ErrSecretNotFound) {
			return fmt.Errorf("secret store password not configured: set R0MP_SECRET_STORE_PASSWORD environment variable, configure InsecureSecretStorePassword, or run setup")
		}
	}

	if err = SetupSecretStorePassword(ctx, cfg); err != nil {
		return fmt.Errorf("failed to setup secret store password: %w", err)
	}
	return nil
}
