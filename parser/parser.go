package parser

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/ngoldack/maskcrypt/engine"
)

type Parser interface {
	Mask(ctx context.Context, key string, data []byte) ([]byte, error)
	Unmask(ctx context.Context, data []byte) ([]byte, error)
	ShouldMask(key string) bool
}

type DefaultParser struct {
	schemePrefix string
	reg          engine.EngineRegistry

	// maskedKeys is a map of keys that should be masked. The key is the key name and the value is the engine ID.
	maskedKeys map[string]string
}

func NewDefaultParser(reg engine.EngineRegistry, opts ...ParserOption) (*DefaultParser, error) {
	if reg == nil {
		return nil, fmt.Errorf("engine registry is nil")
	}
	p := &DefaultParser{
		schemePrefix: "maskcrypt",
		reg:          reg,
		maskedKeys:   make(map[string]string),
	}

	for _, opt := range opts {
		if err := opt(p); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	return p, nil
}

func (d DefaultParser) scheme(id string) string {
	return fmt.Sprintf("%s+%s", d.schemePrefix, id)
}

func (d DefaultParser) getID(scheme string) (string, error) {
	if len(scheme) <= len(d.schemePrefix)+1 {
		return "", fmt.Errorf("invalid scheme: %s", scheme)
	}
	return scheme[len(d.schemePrefix)+1:], nil
}

func (p *DefaultParser) Unmask(ctx context.Context, data []byte) ([]byte, error) {
	url, err := url.Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %w", err)
	}

	id, err := p.getID(url.Scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to get id: %w", err)
	}

	e, err := p.reg.Get(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get engine: %w", err)
	}

	if url.Scheme != p.scheme(e.ID()) {
		return nil, fmt.Errorf("invalid scheme: %s", url.Scheme)
	}

	dec, err := base64.RawStdEncoding.DecodeString(url.Opaque)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	slog.Info("scheme", slog.String("scheme", url.Scheme), slog.String("id", e.ID()), slog.String("opaque", url.Opaque), slog.String("dec", string(dec)))

	decrypted, err := e.Decrypt(ctx, []byte(dec))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return decrypted, nil
}

func (p *DefaultParser) GetEngineID(key string) (id string, ok bool) {
	id, ok = p.maskedKeys[key]
	return
}

func (p *DefaultParser) Mask(ctx context.Context, key string, data []byte) ([]byte, error) {
	eid, ok := p.GetEngineID(key)
	if !ok {
		return nil, fmt.Errorf("engine not found for key: %s", key)
	}

	e, err := p.reg.Get(eid)
	if err != nil {
		return nil, fmt.Errorf("failed to get engine: %w", err)
	}

	enc, err := e.Encrypt(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	encBase64 := base64.RawURLEncoding.EncodeToString(enc)

	encURL := fmt.Sprintf("%s:%s", p.scheme(e.ID()), encBase64)

	// validate url
	_, err = url.Parse(encURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %w", err)
	}

	return []byte(encURL), nil
}

func (p *DefaultParser) ShouldMask(key string) bool {
	_, ok := p.maskedKeys[key]
	return ok
}

var _ Parser = (*DefaultParser)(nil)
