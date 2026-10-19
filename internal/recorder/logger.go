package recorder

import (
	"fmt"
	"log"
)

// Level is the recorder's log level: messages above it are not written.
type Level int

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

// ParseLevel parses error, warn, info or debug.
func ParseLevel(s string) (Level, error) {
	for l, n := range []string{"error", "warn", "info", "debug"} {
		if s == n {
			return Level(l), nil
		}
	}
	return 0, fmt.Errorf("bad log level %q: want error, warn, info or debug", s)
}

// Logger writes messages at or below its level, prefixed with the level
// for errors and warnings.
type Logger struct {
	l     *log.Logger
	level Level
}

func NewLogger(l *log.Logger, level Level) *Logger { return &Logger{l, level} }

func (g *Logger) Errorf(format string, args ...any) { g.write(LevelError, "error: ", format, args) }

func (g *Logger) Warnf(format string, args ...any) { g.write(LevelWarn, "warning: ", format, args) }

// Printf logs at info level.
func (g *Logger) Printf(format string, args ...any) { g.write(LevelInfo, "", format, args) }

func (g *Logger) Debugf(format string, args ...any) { g.write(LevelDebug, "debug: ", format, args) }

func (g *Logger) write(l Level, prefix, format string, args []any) {
	if l <= g.level {
		g.l.Printf(prefix+format, args...)
	}
}
