package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type EngineConfig interface {
	Name() string
}

// GPGConfig holds configuration for GPG encryption engines
type GPGConfig struct {
	name       string `mapstructure:"name"`
	PublicKey  string `mapstructure:"public_key"`
	PrivateKey string `mapstructure:"private_key"`
	Passphrase string `mapstructure:"passphrase"`
}

func (c GPGConfig) Name() string {
	return c.name
}

// AgeConfig holds configuration for Age encryption engines
type AgeConfig struct {
	name string `mapstructure:"name"`
	Key  string `mapstructure:"key"`
}

func (c AgeConfig) Name() string {
	return c.name
}

// MaskCryptConfig holds the complete application configuration
type MaskCryptConfig struct {
	Engine map[string]EngineConfig `mapstructure:"engine"`

	// Maskings defines which fields should be masked
	Maskings []MaskingConfig `mapstructure:"maskings"`
}

type MaskingConfig struct {
	Field  string `mapstructure:"field"`
	Engine string `mapstructure:"engine,omitempty"`
}

// GetGPGConfig retrieves a GPG configuration by name
func (c *MaskCryptConfig) GetGPGConfig(name string) (GPGConfig, bool) {
	if strings.HasPrefix(name, "gpg") {
		if cfg, ok := c.Engine[name].(GPGConfig); ok {
			return cfg, true
		}
	}
	return GPGConfig{}, false
}

// GetAgeConfig retrieves an Age configuration by name
func (c *MaskCryptConfig) GetAgeConfig(name string) (*AgeConfig, bool) {
	if strings.HasPrefix(name, "age") {
		if cfg, ok := c.Engine[name].(AgeConfig); ok {
			return &cfg, true
		}
	}

	return nil, false
}

// LoadConfig loads the application configuration from a file
func LoadConfig() (*MaskCryptConfig, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	err := viper.ReadInConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg MaskCryptConfig
	err = viper.Unmarshal(&cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}
