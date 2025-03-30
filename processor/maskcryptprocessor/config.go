package maskcryptprocessor

import (
	"github.com/ngoldack/maskcrypt/config"
)

type Config struct {
	config.MaskCryptConfig `mapstructure:",squash"`
}
