package parser_test

import (
	"context"
	"testing"

	"github.com/ngoldack/maskcrypt/engine"
	"github.com/ngoldack/maskcrypt/parser"
	"github.com/stretchr/testify/assert"
)

type MockEngine struct {
	original []byte
}

func (m *MockEngine) ID() string {
	return "mock"
}

func (m *MockEngine) Encrypt(_ context.Context, _ []byte) ([]byte, error) {
	return []byte("encrypted"), nil
}

func (m *MockEngine) Decrypt(_ context.Context, _ []byte) ([]byte, error) {
	return m.original, nil
}

var _ engine.Engine = (*MockEngine)(nil)

func Test_DefaultParser(t *testing.T) {
	t.Parallel()
	e := &MockEngine{original: []byte("testdata")}
	p, err := parser.NewDefaultParser(
		engine.NewEngineRegistry(e),
		parser.WithMaskedKey("test", e.ID()),
	)
	assert.NoError(t, err)

	encrypted, err := p.Mask(context.TODO(), "test", []byte("testdata"))
	assert.NoError(t, err)
	t.Logf("encrypted: %s", encrypted)
	decrypted, err := p.Unmask(context.TODO(), encrypted)
	assert.NoError(t, err)
	t.Logf("decrypted: %s", decrypted)

	assert.Equal(t, "testdata", string(decrypted))
}
