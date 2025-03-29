package engine_test

import (
	"context"
	"testing"

	"github.com/ngoldack/maskcrypt/engine"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/stretchr/testify/assert"
)

func NewPGPTestEngine(t *testing.T) *engine.PGPEngine {
	pgp := crypto.PGP()
	testPrivateKey, err := pgp.KeyGeneration().
		AddUserId("John Doe", "john.doe@example.com").
		New().
		GenerateKey()
	assert.NoError(t, err)

	testPublicKey, err := testPrivateKey.ToPublic()
	assert.NoError(t, err)

	pubKeyArmor, err := testPublicKey.Armor()
	assert.NoError(t, err)

	privKeyArmor, err := testPrivateKey.Armor()
	assert.NoError(t, err)

	e, err := engine.NewPGPEngine(pubKeyArmor, privKeyArmor, []byte("passphrase"))
	assert.NoError(t, err)

	return e
}

func Test_PGPEngine_Encrypt(t *testing.T) {
	t.Parallel()
	e := NewPGPTestEngine(t)

	encrypted, err := e.Encrypt(context.TODO(), []byte("testdata"))
	assert.NoError(t, err)
	t.Logf("encrypted: %s", encrypted)

	decrypted, err := e.Decrypt(context.TODO(), encrypted)
	assert.NoError(t, err)
	t.Logf("decrypted: %s", decrypted)

	assert.Equal(t, "testdata", string(decrypted))
}
