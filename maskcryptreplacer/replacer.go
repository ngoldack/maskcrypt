package maskcryptreplacer

import (
	"context"
	"log/slog"

	"github.com/ngoldack/maskcrypt/parser"
)

type replacer struct {
	p parser.Parser
}

type replacerOption func(*replacer) error

type replacerFunc func(groups []string, a slog.Attr) slog.Attr

func New(p parser.Parser, opts ...replacerOption) replacerFunc {
	return func(_ []string, a slog.Attr) slog.Attr {
		if !p.ShouldMask(a.Key) {
			return a
		}

		// Mask the value
		masked, err := p.Mask(context.Background(), a.Key, []byte(a.Value.String()))
		if err != nil {
			return a
		}

		a.Value = slog.StringValue(string(masked))
		return a
	}
}

var _ = slog.HandlerOptions{
	ReplaceAttr: New(nil), // ensure that New() returns a replacerFunc
}
