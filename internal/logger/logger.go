// Package logger builds the application's structured zap logger from
// environment-driven configuration.
package logger

import (
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Config controls logger construction. LogLevel is a zap level name; an unparseable
// value falls back to debug. ProdLogFormat selects the production JSON encoder over
// the development console encoder.
type Config struct {
	LogLevel      string `default:"debug" split_words:"false"`
	ProdLogFormat bool   `default:"false" split_words:"false"`
}

// New constructs a sugared logger. Timestamps are always ISO8601. An invalid
// LogLevel is tolerated by defaulting to debug rather than failing; New returns
// an error only when the underlying encoder cannot be built.
func New(c Config) (*zap.SugaredLogger, error) {
	logLevel := strings.ToLower(c.LogLevel)

	aLevel, err := zap.ParseAtomicLevel(logLevel)
	if err != nil {
		aLevel = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	}

	var cfg zap.Config
	if c.ProdLogFormat {
		cfg = zap.NewProductionConfig()
	} else {
		cfg = zap.NewDevelopmentConfig()
	}

	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.Level = aLevel

	log, err := cfg.Build()
	if err != nil {
		return nil, err
	}

	return log.Sugar(), nil
}
