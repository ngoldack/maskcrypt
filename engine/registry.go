package engine

import (
	"errors"
	"fmt"
)

type EngineRegistry map[string]Engine

var ErrEngineAlreadyRegistered = errors.New("engine already registered")

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
