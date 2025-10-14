package logger

type Level int

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
)

type Logger interface {
	With(field string, value any) Logger
	WithFields(fields map[string]any) Logger
	Logf(level Level, format string, args ...any)
	Errorf(format string, args ...any)
	Warnf(format string, args ...any)
	Infof(format string, args ...any)
	Debugf(format string, args ...any)
	Tracef(format string, args ...any)
}
