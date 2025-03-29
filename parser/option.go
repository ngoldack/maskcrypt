package parser

type ParserOption func(*DefaultParser) error

func WithSchemePrefix(prefix string) ParserOption {
	return func(p *DefaultParser) error {
		p.schemePrefix = prefix
		return nil
	}
}

func WithMaskedKeys(keys map[string]string) ParserOption {
	return func(p *DefaultParser) error {
		if p.maskedKeys == nil {
			p.maskedKeys = make(map[string]string)
		}

		for k, v := range keys {
			p.maskedKeys[k] = v
		}

		return nil
	}
}

func WithMaskedKey(key, engineID string) ParserOption {
	return func(p *DefaultParser) error {
		if p.maskedKeys == nil {
			p.maskedKeys = make(map[string]string)
		}
		p.maskedKeys[key] = engineID
		return nil
	}
}
