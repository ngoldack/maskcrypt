package engine

import (
	"context"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

type PGPEngine struct {
	pgp *crypto.PGPHandle

	publicKey  *crypto.Key
	privateKey *crypto.Key
	passphrase []byte
}

// ID implements Engine.
func (e *PGPEngine) ID() string {
	return "pgp"
}

func NewPGPEngine(pubkey, privkey string, passphrase []byte) (*PGPEngine, error) {
	pgp := crypto.PGPWithProfile(profile.Default())

	publicKey, err := crypto.NewKeyFromArmored(pubkey)
	if err != nil {
		return nil, err
	}
	privateKey, err := crypto.NewPrivateKeyFromArmored(privkey, passphrase)
	if err != nil {
		return nil, err
	}

	return &PGPEngine{
		pgp:        pgp,
		publicKey:  publicKey,
		privateKey: privateKey,
	}, nil
}

// Decrypt implements Decryptor.
func (e *PGPEngine) Decrypt(ctx context.Context, data []byte) ([]byte, error) {
	decHandle, err := e.pgp.Decryption().DecryptionKey(e.privateKey).New()
	if err != nil {
		return nil, err
	}

	decrypted, err := decHandle.Decrypt(data, crypto.Armor)
	if err != nil {
		return nil, err
	}

	return decrypted.Bytes(), nil
}

// Encrypt implements Encryptor.
func (e *PGPEngine) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	encHandle, err := e.pgp.Encryption().Recipient(e.publicKey).New()
	if err != nil {
		return nil, err
	}

	pgpMessage, err := encHandle.Encrypt(data)
	if err != nil {
		return nil, err
	}

	armored, err := pgpMessage.ArmorBytes()
	if err != nil {
		return nil, err
	}

	return armored, nil
}

var _ Engine = (*PGPEngine)(nil)
