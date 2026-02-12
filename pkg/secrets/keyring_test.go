package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

func TestSetAndGetSecretStorePassword(t *testing.T) {

	if !IsKeyringAvailable() {
		t.Skip("Keyring not available on this system")
	}

	cleanup := setKeyringServiceForTesting(t.Name() + uuid.New().String())
	defer func() {
		_ = DeleteSecretStorePasswordFromKeyring()
		cleanup()
	}()
	_ = DeleteSecretStorePasswordFromKeyring()
	testPassword := "test-password-12345"

	err := SetSecretStorePasswordInKeyring(testPassword)
	if err != nil {
		t.Skipf("Keyring not available on this system: %v", err)
	}

	password, err := GetSecretStorePasswordFromKeyring()
	require.NoError(t, err)
	assert.Equal(t, testPassword, password)

	err = DeleteSecretStorePasswordFromKeyring()
	assert.NoError(t, err)

	_, err = GetSecretStorePasswordFromKeyring()
	assert.ErrorIs(t, err, ErrSecretNotFound)
}

func TestDeleteNonExistentPassword(t *testing.T) {
	if !IsKeyringAvailable() {
		t.Skip("Keyring not available on this system")
	}
	cleanup := setKeyringServiceForTesting(t.Name() + uuid.New().String())
	defer func() {
		_ = DeleteSecretStorePasswordFromKeyring()
		cleanup()
	}()
	_ = DeleteSecretStorePasswordFromKeyring()

	err := DeleteSecretStorePasswordFromKeyring()
	assert.NoError(t, err)
}

func TestGetNonExistentPassword(t *testing.T) {
	if !IsKeyringAvailable() {
		t.Skip("Keyring not available on this system")
	}
	cleanup := setKeyringServiceForTesting(t.Name() + uuid.New().String())
	defer func() {
		_ = DeleteSecretStorePasswordFromKeyring()
		cleanup()
	}()
	_ = DeleteSecretStorePasswordFromKeyring()

	_, err := GetSecretStorePasswordFromKeyring()
	if errors.Is(err, keyring.ErrNotFound) {
		t.Skipf("Keyring not available on this system")
	}
	assert.ErrorIs(t, err, ErrSecretNotFound)
}

func TestEnsurePasswordFromConfig_WithExistingPassword(t *testing.T) {
	cfg := &mockConfig{password: "existing-password"}

	err := EnsurePasswordFromConfig(context.Background(), cfg)
	assert.NoError(t, err)
	assert.Equal(t, "existing-password", cfg.password)
}

func TestEnsurePasswordFromConfig_FromKeyring(t *testing.T) {
	cleanup := setKeyringServiceForTesting(t.Name() + uuid.New().String())
	defer func() {
		_ = DeleteSecretStorePasswordFromKeyring()
		cleanup()
	}()
	_ = DeleteSecretStorePasswordFromKeyring()

	testPassword := "keyring-password-123"
	err := SetSecretStorePasswordInKeyring(testPassword)
	if err != nil {
		t.Skipf("Keyring not available on this system: %v", err)
	}

	cfg := &mockConfig{}

	err = EnsurePasswordFromConfig(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, testPassword, cfg.password)
}

type mockConfig struct {
	password         string
	insecurePassword string
}

func (m *mockConfig) Save() error {
	return nil
}

func (m *mockConfig) SetInsecurePassword(password string) {
	m.insecurePassword = password
}

func (m *mockConfig) HasSecretStorePassword() bool {
	return m.password != ""
}

func (m *mockConfig) SetSecretStorePassword(password string) {
	m.password = password
}
