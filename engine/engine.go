package engine

import "context"

type Engine interface {
	Encryptor
	Decryptor
	ID() string
}

type Encryptor interface {
	Encrypt(ctx context.Context, data []byte) ([]byte, error)
}

type Decryptor interface {
	Decrypt(ctx context.Context, data []byte) ([]byte, error)
}
