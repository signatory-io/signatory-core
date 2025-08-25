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
	Log(level Level, format string, args ...any)
	Error(format string, args ...any)
	Warn(format string, args ...any)
	Info(format string, args ...any)
	Debug(format string, args ...any)
	Trace(format string, args ...any)
}
