package ipc

import (
	"io"

	"github.com/rs/zerolog"
)

// ipcLogWriter sends log messages as IPC messages
type ipcLogWriter struct {
	messageSink io.Writer
}

func (ilw *ipcLogWriter) Write(p []byte) (n int, err error) {
	err = writeMessageNext(ilw.messageSink, &Message{Command: CmdLog, Data: p})

	// is this correct?!
	if err == nil {
		n = len(p)
	}

	return
}

// levlFilterLogWriter filters out messages below a set log level
type levlFilterLogWriter struct {
	level zerolog.Level
	lw    zerolog.LevelWriter
}

func (lflw *levlFilterLogWriter) WriteLevel(l zerolog.Level, p []byte) (n int, err error) {
	if l >= lflw.level {
		n, err = lflw.lw.WriteLevel(l, p)
	} else {
		// pretend to behave to make our log master happy
		n = len(p)
	}
	return
}

func (lflw *levlFilterLogWriter) Write(p []byte) (n int, err error) {
	n, err = lflw.lw.Write(p)
	return
}

type levelWriterAdapter struct {
	io.Writer
}

func (lw levelWriterAdapter) WriteLevel(l zerolog.Level, p []byte) (n int, err error) {
	return lw.Write(p)
}

func wrapLevelAdapter(w io.Writer, lvl zerolog.Level) io.Writer {
	if lw, ok := w.(zerolog.LevelWriter); ok {
		return &levlFilterLogWriter{lw: lw, level: lvl}
	}
	return &levlFilterLogWriter{lw: levelWriterAdapter{w}, level: lvl}
}

// GetSharedLog gets a shared logger that sends log output over log sinks both using different levels
func GetSharedLog(baseLogger *zerolog.Logger, w1, w2 io.Writer, l1, l2 zerolog.Level) *zerolog.Logger {
	minLvl := l1
	if l2 < minLvl {
		minLvl = l2
	}
	lvla := wrapLevelAdapter(w1, l1)
	lvlb := wrapLevelAdapter(w2, l2)
	sharedLogger := baseLogger.Output(zerolog.MultiLevelWriter(lvla, lvlb)).Level(minLvl)
	return &sharedLogger
}
