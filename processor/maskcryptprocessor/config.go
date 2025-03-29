package maskcryptprocessor

import "go.opentelemetry.io/collector/processor"

type Config struct {
	processor.Settings `mapstructure:",squash"`
}
