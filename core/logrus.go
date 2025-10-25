package core

import (
	"github.com/signatory-io/signatory-core/logger"
	"github.com/sirupsen/logrus"
)

type LogrusAdapter struct {
	*logrus.Logger
}

type logrusEntryAdapter struct {
	*logrus.Entry
}

func logrusLevel(l logger.Level) logrus.Level {
	switch l {
	case logger.LevelDebug:
		return logrus.DebugLevel
	case logger.LevelError:
		return logrus.ErrorLevel
	case logger.LevelTrace:
		return logrus.TraceLevel
	case logger.LevelWarn:
		return logrus.WarnLevel
	default:
		return logrus.InfoLevel
	}
}

func (l LogrusAdapter) Logf(level logger.Level, format string, args ...any) {
	l.Logger.Logf(logrusLevel(level), format, args...)
}

func (l LogrusAdapter) Log(level logger.Level, args ...any) {
	l.Logger.Log(logrusLevel(level), args...)
}

func (l LogrusAdapter) With(field string, value any) logger.Logger {
	return logrusEntryAdapter{Entry: l.Logger.WithField(field, value)}
}

func (l LogrusAdapter) WithFields(fields map[string]any) logger.Logger {
	return logrusEntryAdapter{Entry: l.Logger.WithFields(fields)}
}

func (l logrusEntryAdapter) Logf(level logger.Level, format string, args ...any) {
	l.Entry.Logf(logrusLevel(level), format, args...)
}

func (l logrusEntryAdapter) Log(level logger.Level, args ...any) {
	l.Entry.Log(logrusLevel(level), args...)
}

func (l logrusEntryAdapter) With(field string, value any) logger.Logger {
	return logrusEntryAdapter{Entry: l.Entry.WithField(field, value)}
}

func (l logrusEntryAdapter) WithFields(fields map[string]any) logger.Logger {
	return logrusEntryAdapter{Entry: l.Entry.WithFields(fields)}
}

var _ logger.Logger = (*LogrusAdapter)(nil)
