package secrets

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecretStore(t *testing.T) {
	store := NewSecretStore("test-password")
	require.NotNil(t, store)
	assert.True(t, store.locked)
	assert.NotNil(t, store.buff)
}

func TestSecretStoreUnlockAndCreate(t *testing.T) {
	store := NewSecretStore("test-password")
	require.NotNil(t, store)

	err := store.Unlock()
	require.NoError(t, err)
	assert.False(t, store.locked)
	assert.NotNil(t, store.db)
}

func TestSecretStoreSetAndGet(t *testing.T) {
	store := NewSecretStore("test-password")
	require.NotNil(t, store)

	err := store.Unlock()
	require.NoError(t, err)

	err = store.SetSecret("my-key", "my-secret-value")
	require.NoError(t, err)

	val, err := store.GetSecret("my-key")
	require.NoError(t, err)
	assert.Equal(t, "my-secret-value", val)

	_, err = store.GetSecret("non-existent-key")
	assert.ErrorIs(t, err, ErrEntryNotFound)
}

func TestSecretStoreUpdate(t *testing.T) {
	store := NewSecretStore("test-password")
	require.NotNil(t, store)

	err := store.Unlock()
	require.NoError(t, err)

	err = store.SetSecret("my-key", "original-value")
	require.NoError(t, err)

	val, err := store.GetSecret("my-key")
	require.NoError(t, err)
	assert.Equal(t, "original-value", val)

	err = store.SetSecret("my-key", "updated-value")
	require.NoError(t, err)

	val, err = store.GetSecret("my-key")
	require.NoError(t, err)
	assert.Equal(t, "updated-value", val)
}

func TestSecretStorePersistence(t *testing.T) {
	store1 := NewSecretStore("test-password")
	require.NotNil(t, store1)
	
	err := store1.Unlock()
	require.NoError(t, err)
	
	err = store1.SetSecret("persistent-key", "persistent-value")
	require.NoError(t, err)
	
	// Lock to save changes to buffer
	err = store1.Lock()
	require.NoError(t, err)
	
	// Get the serialized data
	savedData := store1.Bytes()
	require.NotEmpty(t, savedData)

	// Create a new store and load the data
	store2 := NewSecretStore("test-password")
	require.NotNil(t, store2)
	
	_, err = store2.Write(savedData)
	require.NoError(t, err)
	
	err = store2.Unlock()
	require.NoError(t, err)

	val, err := store2.GetSecret("persistent-key")
	require.NoError(t, err)
	assert.Equal(t, "persistent-value", val)
}

func TestSecretStoreSSHKey(t *testing.T) {
	store := NewSecretStore("test-password")
	require.NotNil(t, store)

	err := store.Unlock()
	require.NoError(t, err)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	err = store.SetSSHKey("my-ssh-key", privateKey)
	require.NoError(t, err)

	retrievedKey, err := store.GetSSHKey("my-ssh-key")
	require.NoError(t, err)
	assert.NotNil(t, retrievedKey)

	assert.Equal(t, privateKey.N, retrievedKey.N)
	assert.Equal(t, privateKey.E, retrievedKey.E)
	assert.Equal(t, privateKey.D, retrievedKey.D)
}

func TestSecretStoreLockedOperations(t *testing.T) {
	store := NewSecretStore("test-password")
	require.NotNil(t, store)

	_, err := store.GetSecret("key")
	assert.ErrorIs(t, err, ErrDatabaseNotUnlocked)

	err = store.SetSecret("key", "value")
	assert.ErrorIs(t, err, ErrDatabaseNotUnlocked)

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	err = store.SetSSHKey("key", privateKey)
	assert.ErrorIs(t, err, ErrDatabaseNotUnlocked)

	_, err = store.GetSSHKey("key")
	assert.ErrorIs(t, err, ErrDatabaseNotUnlocked)
}

func TestSecretStoreReset(t *testing.T) {
	store := NewSecretStore("test-password")
	require.NotNil(t, store)

	err := store.Unlock()
	require.NoError(t, err)

	err = store.SetSecret("test-key", "test-value")
	require.NoError(t, err)

	err = store.Lock()
	require.NoError(t, err)

	// Verify buffer has data
	assert.NotEmpty(t, store.Bytes())

	// Reset should clear the buffer
	store.Reset()
	assert.Empty(t, store.Bytes())
}

func TestSecretStoreWrongPassword(t *testing.T) {
	store1 := NewSecretStore("correct-password")
	require.NotNil(t, store1)

	err := store1.Unlock()
	require.NoError(t, err)

	err = store1.SetSecret("secret-key", "secret-value")
	require.NoError(t, err)

	err = store1.Lock()
	require.NoError(t, err)

	savedData := store1.Bytes()
	require.NotEmpty(t, savedData)

	// Try to unlock with wrong password
	store2 := NewSecretStore("wrong-password")
	_, err = store2.Write(savedData)
	require.NoError(t, err)

	err = store2.Unlock()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode database")
}

func TestSecretStoreGetSSHKeyNotFound(t *testing.T) {
	store := NewSecretStore("test-password")
	require.NotNil(t, store)

	err := store.Unlock()
	require.NoError(t, err)

	_, err = store.GetSSHKey("non-existent-key")
	assert.ErrorIs(t, err, ErrEntryNotFound)
}

func TestSecretStoreGetSSHKeyInvalidData(t *testing.T) {
	store := NewSecretStore("test-password")
	require.NotNil(t, store)

	err := store.Unlock()
	require.NoError(t, err)

	// Store invalid PEM data
	err = store.SetSecret("invalid-ssh-key", "not-a-valid-pem-key")
	require.NoError(t, err)

	_, err = store.GetSSHKey("invalid-ssh-key")
	assert.ErrorIs(t, err, ErrInvalidSSHKey)
}

func TestSecretStoreMultipleSecrets(t *testing.T) {
	store := NewSecretStore("test-password")
	require.NotNil(t, store)

	err := store.Unlock()
	require.NoError(t, err)

	// Store multiple secrets
	secrets := map[string]string{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}

	for key, val := range secrets {
		err = store.SetSecret(key, val)
		require.NoError(t, err)
	}

	// Verify all secrets can be retrieved
	for key, expectedVal := range secrets {
		val, err := store.GetSecret(key)
		require.NoError(t, err)
		assert.Equal(t, expectedVal, val)
	}
}

func TestSecretStoreLockUnlockCycle(t *testing.T) {
	store := NewSecretStore("test-password")
	require.NotNil(t, store)

	// First unlock (creates new database)
	err := store.Unlock()
	require.NoError(t, err)
	assert.False(t, store.locked)

	err = store.SetSecret("key1", "value1")
	require.NoError(t, err)

	// Lock
	err = store.Lock()
	require.NoError(t, err)

	// Unlock again (should load from buffer)
	err = store.Unlock()
	require.NoError(t, err)
	assert.False(t, store.locked)

	// Verify data persisted
	val, err := store.GetSecret("key1")
	require.NoError(t, err)
	assert.Equal(t, "value1", val)
}

func TestSecretStoreReadWrite(t *testing.T) {
	store1 := NewSecretStore("test-password")
	require.NotNil(t, store1)

	err := store1.Unlock()
	require.NoError(t, err)

	err = store1.SetSecret("test", "data")
	require.NoError(t, err)

	err = store1.Lock()
	require.NoError(t, err)

	// Read from store1
	data := make([]byte, store1.buff.Len())
	n, err := store1.Read(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)

	// Write to store2
	store2 := NewSecretStore("test-password")
	n, err = store2.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)

	err = store2.Unlock()
	require.NoError(t, err)

	val, err := store2.GetSecret("test")
	require.NoError(t, err)
	assert.Equal(t, "data", val)
}

func TestSecretStoreListSecrets(t *testing.T) {
	t.Run("list empty store", func(t *testing.T) {
		store := NewSecretStore("test-password")
		require.NotNil(t, store)

		err := store.Unlock()
		require.NoError(t, err)

		keys, err := store.ListSecrets()
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("list single secret", func(t *testing.T) {
		store := NewSecretStore("test-password")
		require.NotNil(t, store)

		err := store.Unlock()
		require.NoError(t, err)

		err = store.SetSecret("key1", "value1")
		require.NoError(t, err)

		keys, err := store.ListSecrets()
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.Contains(t, keys, "key1")
	})

	t.Run("list multiple secrets", func(t *testing.T) {
		store := NewSecretStore("test-password")
		require.NotNil(t, store)

		err := store.Unlock()
		require.NoError(t, err)

		secrets := map[string]string{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
		}

		for key, val := range secrets {
			err = store.SetSecret(key, val)
			require.NoError(t, err)
		}

		keys, err := store.ListSecrets()
		require.NoError(t, err)
		assert.Len(t, keys, 3)
		
		for key := range secrets {
			assert.Contains(t, keys, key)
		}
	})

	t.Run("list secrets when locked", func(t *testing.T) {
		store := NewSecretStore("test-password")
		require.NotNil(t, store)

		keys, err := store.ListSecrets()
		assert.ErrorIs(t, err, ErrDatabaseNotUnlocked)
		assert.Nil(t, keys)
	})

	t.Run("list secrets after update", func(t *testing.T) {
		store := NewSecretStore("test-password")
		require.NotNil(t, store)

		err := store.Unlock()
		require.NoError(t, err)

		err = store.SetSecret("key1", "original")
		require.NoError(t, err)

		// Update existing key shouldn't duplicate
		err = store.SetSecret("key1", "updated")
		require.NoError(t, err)

		keys, err := store.ListSecrets()
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.Contains(t, keys, "key1")
	})
}

func TestSecretStoreMerge(t *testing.T) {
	t.Run("merge into empty store", func(t *testing.T) {
		store1 := NewSecretStore("test-password")
		require.NotNil(t, store1)
		err := store1.Unlock()
		require.NoError(t, err)

		store2 := NewSecretStore("test-password")
		require.NotNil(t, store2)
		err = store2.Unlock()
		require.NoError(t, err)

		err = store2.SetSecret("key1", "value1")
		require.NoError(t, err)
		err = store2.SetSecret("key2", "value2")
		require.NoError(t, err)

		// Merge store2 into store1
		err = store1.Merge(store2)
		require.NoError(t, err)

		// Verify store1 has all secrets from store2
		val, err := store1.GetSecret("key1")
		require.NoError(t, err)
		assert.Equal(t, "value1", val)

		val, err = store1.GetSecret("key2")
		require.NoError(t, err)
		assert.Equal(t, "value2", val)
	})

	t.Run("merge with overlapping keys - other takes precedence", func(t *testing.T) {
		store1 := NewSecretStore("test-password")
		require.NotNil(t, store1)
		err := store1.Unlock()
		require.NoError(t, err)

		err = store1.SetSecret("shared-key", "original-value")
		require.NoError(t, err)
		err = store1.SetSecret("unique-to-store1", "value1")
		require.NoError(t, err)

		store2 := NewSecretStore("test-password")
		require.NotNil(t, store2)
		err = store2.Unlock()
		require.NoError(t, err)

		err = store2.SetSecret("shared-key", "updated-value")
		require.NoError(t, err)
		err = store2.SetSecret("unique-to-store2", "value2")
		require.NoError(t, err)

		// Merge store2 into store1
		err = store1.Merge(store2)
		require.NoError(t, err)

		// Verify shared-key was updated with value from store2
		val, err := store1.GetSecret("shared-key")
		require.NoError(t, err)
		assert.Equal(t, "updated-value", val, "other store's value should take precedence")

		// Verify unique keys from both stores exist
		val, err = store1.GetSecret("unique-to-store1")
		require.NoError(t, err)
		assert.Equal(t, "value1", val)

		val, err = store1.GetSecret("unique-to-store2")
		require.NoError(t, err)
		assert.Equal(t, "value2", val)

		// Verify total count
		keys, err := store1.ListSecrets()
		require.NoError(t, err)
		assert.Len(t, keys, 3)
	})

	t.Run("merge from empty store", func(t *testing.T) {
		store1 := NewSecretStore("test-password")
		require.NotNil(t, store1)
		err := store1.Unlock()
		require.NoError(t, err)

		err = store1.SetSecret("key1", "value1")
		require.NoError(t, err)

		store2 := NewSecretStore("test-password")
		require.NotNil(t, store2)
		err = store2.Unlock()
		require.NoError(t, err)

		// Merge empty store2 into store1
		err = store1.Merge(store2)
		require.NoError(t, err)

		// Verify store1 still has its original secret
		val, err := store1.GetSecret("key1")
		require.NoError(t, err)
		assert.Equal(t, "value1", val)

		keys, err := store1.ListSecrets()
		require.NoError(t, err)
		assert.Len(t, keys, 1)
	})

	t.Run("merge when locked", func(t *testing.T) {
		store1 := NewSecretStore("test-password")
		require.NotNil(t, store1)

		store2 := NewSecretStore("test-password")
		require.NotNil(t, store2)
		err := store2.Unlock()
		require.NoError(t, err)

		// Try to merge into locked store
		err = store1.Merge(store2)
		assert.ErrorIs(t, err, ErrDatabaseNotUnlocked)
	})

	t.Run("merge with multiple secrets", func(t *testing.T) {
		store1 := NewSecretStore("test-password")
		require.NotNil(t, store1)
		err := store1.Unlock()
		require.NoError(t, err)

		for i := 1; i <= 5; i++ {
			key := fmt.Sprintf("base-key-%d", i)
			val := fmt.Sprintf("base-value-%d", i)
			err = store1.SetSecret(key, val)
			require.NoError(t, err)
		}

		store2 := NewSecretStore("test-password")
		require.NotNil(t, store2)
		err = store2.Unlock()
		require.NoError(t, err)

		for i := 4; i <= 8; i++ {
			key := fmt.Sprintf("base-key-%d", i)
			val := fmt.Sprintf("new-value-%d", i)
			err = store2.SetSecret(key, val)
			require.NoError(t, err)
		}

		// Merge store2 into store1
		err = store1.Merge(store2)
		require.NoError(t, err)

		// Verify we have keys 1-8
		keys, err := store1.ListSecrets()
		require.NoError(t, err)
		assert.Len(t, keys, 8)

		// Verify keys 1-3 have original values
		for i := 1; i <= 3; i++ {
			key := fmt.Sprintf("base-key-%d", i)
			val, err := store1.GetSecret(key)
			require.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("base-value-%d", i), val)
		}

		// Verify keys 4-5 have updated values from store2
		for i := 4; i <= 5; i++ {
			key := fmt.Sprintf("base-key-%d", i)
			val, err := store1.GetSecret(key)
			require.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("new-value-%d", i), val)
		}

		// Verify keys 6-8 have values from store2
		for i := 6; i <= 8; i++ {
			key := fmt.Sprintf("base-key-%d", i)
			val, err := store1.GetSecret(key)
			require.NoError(t, err)
			assert.Equal(t, fmt.Sprintf("new-value-%d", i), val)
		}
	})

	t.Run("merge persists after lock/unlock", func(t *testing.T) {
		store1 := NewSecretStore("test-password")
		require.NotNil(t, store1)
		err := store1.Unlock()
		require.NoError(t, err)

		err = store1.SetSecret("original-key", "original-value")
		require.NoError(t, err)

		store2 := NewSecretStore("test-password")
		require.NotNil(t, store2)
		err = store2.Unlock()
		require.NoError(t, err)

		err = store2.SetSecret("merged-key", "merged-value")
		require.NoError(t, err)

		// Merge and lock
		err = store1.Merge(store2)
		require.NoError(t, err)

		err = store1.Lock()
		require.NoError(t, err)

		// Unlock and verify merged data persisted
		err = store1.Unlock()
		require.NoError(t, err)

		val, err := store1.GetSecret("original-key")
		require.NoError(t, err)
		assert.Equal(t, "original-value", val)

		val, err = store1.GetSecret("merged-key")
		require.NoError(t, err)
		assert.Equal(t, "merged-value", val)
	})
}
