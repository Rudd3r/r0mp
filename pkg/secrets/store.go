package secrets

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/Rudd3r/r0mp/pkg/domain"
	"github.com/tobischo/gokeepasslib/v3"
	"github.com/tobischo/gokeepasslib/v3/wrappers"
)

var _ domain.SecretReadWriter = (*SecretStore)(nil)

var (
	ErrDatabaseNotUnlocked = errors.New("database not unlocked")
	ErrEntryNotFound       = errors.New("entry not found")
	ErrInvalidSSHKey       = errors.New("invalid SSH key format")
)

type SecretStore struct {
	buff   *bytes.Buffer
	db     *gokeepasslib.Database
	pass   string
	locked bool
}

func NewSecretStore(pass string) *SecretStore {
	return &SecretStore{
		buff:   &bytes.Buffer{},
		pass:   pass,
		locked: true,
	}
}

func (s *SecretStore) Reset() {
	s.buff.Reset()
}

func (s *SecretStore) Bytes() []byte {
	return s.buff.Bytes()
}

func (s *SecretStore) Read(p []byte) (n int, err error) {
	return s.buff.Read(p)
}

func (s *SecretStore) Write(p []byte) (n int, err error) {
	return s.buff.Write(p)
}

func (s *SecretStore) Unlock() error {

	if s.buff.Len() == 0 {
		s.createNewDatabase(s.pass)
		return nil
	}

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(s.pass)

	if err := gokeepasslib.NewDecoder(s).Decode(db); err != nil {
		return fmt.Errorf("failed to decode database: %w", err)
	}

	if err := db.UnlockProtectedEntries(); err != nil {
		return fmt.Errorf("failed to unlock protected entries: %w", err)
	}

	s.db = db
	s.locked = false

	return nil
}

func (s *SecretStore) createNewDatabase(pass string) {
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(pass)

	rootGroup := gokeepasslib.NewGroup()
	rootGroup.Name = "Root"

	db.Content = &gokeepasslib.DBContent{
		Meta: gokeepasslib.NewMetaData(),
		Root: &gokeepasslib.RootData{
			Groups: []gokeepasslib.Group{rootGroup},
		},
	}

	s.db = db
	s.locked = false
}

func (s *SecretStore) GetSecret(key string) (string, error) {
	if s.locked || s.db == nil {
		return "", ErrDatabaseNotUnlocked
	}

	entry := s.findEntry(key)
	if entry == nil {
		return "", ErrEntryNotFound
	}

	return entry.GetPassword(), nil
}

func (s *SecretStore) SetSecret(key, val string) error {
	if s.locked || s.db == nil {
		return ErrDatabaseNotUnlocked
	}

	entry := s.findEntry(key)
	if entry != nil {
		entry.Values = append(entry.Values[:0],
			gokeepasslib.ValueData{Key: "Title", Value: gokeepasslib.V{Content: key}},
			gokeepasslib.ValueData{Key: "Password", Value: gokeepasslib.V{Content: val, Protected: wrappers.NewBoolWrapper(true)}},
		)
	} else {
		newEntry := gokeepasslib.NewEntry()
		newEntry.Values = []gokeepasslib.ValueData{
			{Key: "Title", Value: gokeepasslib.V{Content: key}},
			{Key: "Password", Value: gokeepasslib.V{Content: val, Protected: wrappers.NewBoolWrapper(true)}},
		}

		if len(s.db.Content.Root.Groups) == 0 {
			rootGroup := gokeepasslib.NewGroup()
			rootGroup.Name = "Root"
			s.db.Content.Root.Groups = []gokeepasslib.Group{rootGroup}
		}

		s.db.Content.Root.Groups[0].Entries = append(s.db.Content.Root.Groups[0].Entries, newEntry)
	}

	return nil
}

func (s *SecretStore) SetSSHKey(key string, sshKey *rsa.PrivateKey) error {
	if s.locked || s.db == nil {
		return ErrDatabaseNotUnlocked
	}

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(sshKey),
	})

	return s.SetSecret(key, string(pemData))
}

func (s *SecretStore) GetSSHKey(key string) (*rsa.PrivateKey, error) {
	if s.locked || s.db == nil {
		return nil, ErrDatabaseNotUnlocked
	}

	pemData, err := s.GetSecret(key)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, ErrInvalidSSHKey
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH key: %w", err)
	}

	return privateKey, nil
}

func (s *SecretStore) findEntry(title string) *gokeepasslib.Entry {
	if s.db == nil || s.db.Content == nil || s.db.Content.Root == nil {
		return nil
	}

	for i := range s.db.Content.Root.Groups {
		for j := range s.db.Content.Root.Groups[i].Entries {
			entry := &s.db.Content.Root.Groups[i].Entries[j]
			if entry.GetTitle() == title {
				return entry
			}
		}
	}

	return nil
}

func (s *SecretStore) Lock() error {
	if err := s.db.LockProtectedEntries(); err != nil {
		return fmt.Errorf("failed to lock protected entries: %w", err)
	}

	s.buff.Truncate(0)
	encoder := gokeepasslib.NewEncoder(s)
	if err := encoder.Encode(s.db); err != nil {
		return fmt.Errorf("failed to encode database: %w", err)
	}

	return nil
}

// ListSecrets returns all secret keys (titles) in the database
func (s *SecretStore) ListSecrets() ([]string, error) {
	if s.locked || s.db == nil {
		return nil, ErrDatabaseNotUnlocked
	}

	var keys []string
	if s.db.Content == nil || s.db.Content.Root == nil {
		return keys, nil
	}

	for i := range s.db.Content.Root.Groups {
		for j := range s.db.Content.Root.Groups[i].Entries {
			entry := &s.db.Content.Root.Groups[i].Entries[j]
			title := entry.GetTitle()
			if title != "" {
				keys = append(keys, title)
			}
		}
	}

	return keys, nil
}

// Merge merges secrets from another SecretReadWriter into this one
// Secrets from 'other' take precedence over existing secrets with the same key
func (s *SecretStore) Merge(other domain.SecretReadWriter) error {
	if s.locked || s.db == nil {
		return ErrDatabaseNotUnlocked
	}

	// List all secrets from the other store
	keys, err := other.ListSecrets()
	if err != nil {
		return fmt.Errorf("failed to list secrets from other store: %w", err)
	}

	// Copy each secret from other to this store
	for _, key := range keys {
		value, err := other.GetSecret(key)
		if err != nil {
			return fmt.Errorf("failed to get secret %s from other store: %w", key, err)
		}

		// Set the secret in this store (will update if exists, create if not)
		if err := s.SetSecret(key, value); err != nil {
			return fmt.Errorf("failed to set secret %s: %w", key, err)
		}
	}

	return nil
}
