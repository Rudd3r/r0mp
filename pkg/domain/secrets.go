package domain

import (
	"crypto/rsa"
	"io"
)

type SecretReadWriter interface {
	io.Reader
	io.Writer
	Reset()
	Bytes() []byte
	Unlock() error
	Lock() error
	GetSecret(key string) (string, error)
	SetSecret(key, val string) error
	SetSSHKey(key string, sshKey *rsa.PrivateKey) error
	GetSSHKey(key string) (*rsa.PrivateKey, error)
	ListSecrets() ([]string, error)
	Merge(other SecretReadWriter) error
}
