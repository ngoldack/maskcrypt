package config

import (
	"context"
	"fmt"

	"github.com/spf13/viper"
)

type MaskCryptConfig struct {
	Engine struct {
		GPG struct {
			PrivateKey string `mapstructure:"private_key"`
			PublicKey  string `mapstructure:"public_key"`
		} `mapstructure:"gpg"`
	} `mapstructure:"engine"`

	Masks []struct {
		Field  string `mapstructure:"field"`
		Engine string `mapstructure:"engine"`
	} `mapstructure:"masks"`
}

func LoadConfig(ctx context.Context) (*MaskCryptConfig, error) {
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
