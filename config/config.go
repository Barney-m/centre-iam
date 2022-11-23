package config

import (
	"time"

	"github.com/spf13/viper"
)

type CentreConfig struct {
	TokenSymmetricKey    string        `mapstructure:"TOKEN_SYMMETRIC_KEY"`
	AccessTokenDuration  time.Duration `mapstructure:"ACCESS_TOKEN_DURATION"`
	RefreshTokenDuration time.Duration `mapstructure:"REFRESH_TOKEN_DURATION"`
	DatabaseUrl          string        `mapstructure:"DATABASE_URL"`
}

var Config *CentreConfig

func LoadConfig() (err error) {
	viper.AddConfigPath("./")
	viper.SetConfigName("centre")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	err = viper.ReadInConfig()

	if err != nil {
		return
	}

	err = viper.Unmarshal(&Config)
	return
}
