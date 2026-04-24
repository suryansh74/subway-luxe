package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Log *zap.SugaredLogger

func Init(mode string) error {
	var cfg zap.Config

	switch mode {
	case "development", "dev", "debug":
		cfg = zap.NewDevelopmentConfig()
		cfg.Level.SetLevel(zapcore.DebugLevel)
	case "production", "prod":
		cfg = zap.NewProductionConfig()
		cfg.Level.SetLevel(zapcore.InfoLevel)
	default:
		cfg = zap.NewDevelopmentConfig()
		cfg.Level.SetLevel(zapcore.DebugLevel)
	}

	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	logger, err := cfg.Build()
	if err != nil {
		return err
	}

	Log = logger.Sugar()
	return nil
}

func InitWithPath(logPath string, logLevel string) error {
	cfg := zap.NewProductionConfig()

	level := zapcore.InfoLevel
	switch logLevel {
	case "debug":
		level = zapcore.DebugLevel
	case "warn":
		level = zapcore.WarnLevel
	case "error":
		level = zapcore.ErrorLevel
	}
	cfg.Level.SetLevel(level)

	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	if logPath != "" {
		cfg.OutputPaths = []string{logPath}
		cfg.ErrorOutputPaths = []string{logPath}
	}

	logger, err := cfg.Build()
	if err != nil {
		return err
	}

	Log = logger.Sugar()
	return nil
}

func Sync() {
	if Log != nil {
		_ = Log.Sync()
	}
}

func Debug(msg string, keysAndValues ...interface{}) {
	Log.Debugw(msg, keysAndValues...)
}

func Info(msg string, keysAndValues ...interface{}) {
	Log.Infow(msg, keysAndValues...)
}

func Warn(msg string, keysAndValues ...interface{}) {
	Log.Warnw(msg, keysAndValues...)
}

func Error(msg string, keysAndValues ...interface{}) {
	Log.Errorw(msg, keysAndValues...)
}

func Fatal(msg string, keysAndValues ...interface{}) {
	Log.Fatalw(msg, keysAndValues...)
}

func With(keysAndValues ...interface{}) *zap.SugaredLogger {
	return Log.With(keysAndValues...)
}
