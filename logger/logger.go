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
	Log(level Level, args ...any)
	Errorf(format string, args ...any)
	Error(args ...any)
	Warnf(format string, args ...any)
	Warn(args ...any)
	Infof(format string, args ...any)
	Info(args ...any)
	Debugf(format string, args ...any)
	Debug(args ...any)
	Tracef(format string, args ...any)
	Trace(args ...any)
}
