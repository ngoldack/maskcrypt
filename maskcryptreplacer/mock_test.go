package maskcryptreplacer_test

import (
	"context"

	"github.com/ngoldack/maskcrypt/parser"
)

type mockParser struct {
	original []byte
	key      string
}

var _ parser.Parser = (*mockParser)(nil)

func (m mockParser) Mask(_ context.Context, _ string, data []byte) ([]byte, error) {
	return []byte("masked"), nil
}

func (m mockParser) Unmask(_ context.Context, data []byte) ([]byte, error) {
	return m.original, nil
}

func (m *mockParser) ShouldMask(key string) bool {
	return key == m.key
}

func NewMockParser(key, data string) *mockParser {
	return &mockParser{
		original: []byte(data),
	}
}
