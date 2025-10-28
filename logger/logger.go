package logger

import (
	"fmt"
	"strconv"
	"strings"
)

type Level int

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
)

func (l Level) MarshalText() (text []byte, err error) {
	switch l {
	case LevelDebug:
		return []byte("debug"), nil
	case LevelError:
		return []byte("error"), nil
	case LevelInfo:
		return []byte("info"), nil
	case LevelTrace:
		return []byte("trace"), nil
	case LevelWarn:
		return []byte("warn"), nil
	default:
		panic(fmt.Sprintf("unexpected logger.Level: %d", l))
	}
}

func (l Level) String() string {
	text, err := l.MarshalText()
	if err != nil {
		return strconv.FormatInt(int64(l), 10)
	}
	return string(text)
}

func (l *Level) UnmarshalText(text []byte) error {
	switch {
	case strings.EqualFold(string(text), "error"):
		*l = LevelError
	case strings.EqualFold(string(text), "warn"):
		*l = LevelWarn
	case strings.EqualFold(string(text), "info"):
		*l = LevelInfo
	case strings.EqualFold(string(text), "debug"):
		*l = LevelDebug
	case strings.EqualFold(string(text), "trace"):
		*l = LevelTrace
	default:
		return fmt.Errorf("unknown log level: %s", string(text))
	}
	return nil
}

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
