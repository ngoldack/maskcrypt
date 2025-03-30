package engine

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/ngoldack/maskcrypt/config"
)

type EngineRegistry map[string]Engine

var ErrEngineAlreadyRegistered = errors.New("engine already registered")

func GetEngines(cfg *config.MaskCryptConfig) ([]Engine, error) {
	engines := make([]Engine, 0)

	for k := range cfg.Engine {
		if strings.HasPrefix(k, "age") {
			// skip
			continue
		}

		if strings.HasPrefix(k, "gpg") {
			gpgCfg, ok := cfg.GetGPGConfig(k)
			if !ok {
				return nil, fmt.Errorf("error getting GPG config: %s", k)
			}

			gpgEngine, err := NewPGPEngine(k, gpgCfg.PublicKey, gpgCfg.PrivateKey, []byte(gpgCfg.Passphrase))
			if err != nil {
				return nil, fmt.Errorf("error creating a PGP engine: %w", err)
			}

			engines = append(engines, gpgEngine)
		}
	}

	log.Printf("engines: %v", engines)

	return engines, nil

}

func NewEngineRegistry(engines ...Engine) EngineRegistry {
	r := make(EngineRegistry, len(engines))
	for _, e := range engines {
		r[e.ID()] = e
	}
	return r
}

func (r EngineRegistry) Register(e Engine) error {
	if _, ok := r[e.ID()]; ok {
		return fmt.Errorf("%w: %s", ErrEngineAlreadyRegistered, e.ID())
	}
	r[e.ID()] = e
	return nil
}

func (r EngineRegistry) Get(id string) (Engine, error) {
	e, ok := r[id]
	if !ok {
		return nil, fmt.Errorf("engine not found: %s", id)
	}
	return e, nil
}
