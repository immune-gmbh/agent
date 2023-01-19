//go:build windows

package winsvc

import (
	"github.com/rs/zerolog"
	"golang.org/x/sys/windows/svc/eventlog"
)

// eventLogWriter writes logs to the windows event log and is not thread safe in any way
type eventLogWriter struct {
	elog *eventlog.Log
	cw   *zerolog.ConsoleWriter
}

// kudos to this guy for the pretty wild trick:
// https://stackoverflow.com/a/67290960
type writerFunc func(p []byte) (n int, err error)

func (wf writerFunc) Write(p []byte) (n int, err error) {
	return wf(p)
}

func (ew *eventLogWriter) Write(p []byte) (n int, err error) {
	ew.cw.Out = writerFunc(func(p []byte) (n int, err error) {
		return len(p), ew.elog.Info(4, string(p))
	})
	return ew.cw.Write(p)
}

func (ew *eventLogWriter) WriteLevel(level zerolog.Level, p []byte) (n int, err error) {
	switch level {
	case zerolog.NoLevel:
		ew.cw.Out = writerFunc(func(p []byte) (n int, err error) {
			return len(p), ew.elog.Info(4, string(p))
		})
	case zerolog.TraceLevel:
		ew.cw.Out = writerFunc(func(p []byte) (n int, err error) {
			return len(p), ew.elog.Info(3, string(p))
		})
	case zerolog.DebugLevel:
		ew.cw.Out = writerFunc(func(p []byte) (n int, err error) {
			return len(p), ew.elog.Info(2, string(p))
		})
	case zerolog.InfoLevel:
		ew.cw.Out = writerFunc(func(p []byte) (n int, err error) {
			return len(p), ew.elog.Info(1, string(p))
		})
	case zerolog.WarnLevel:
		ew.cw.Out = writerFunc(func(p []byte) (n int, err error) {
			return len(p), ew.elog.Warning(1, string(p))
		})
	case zerolog.ErrorLevel:
		ew.cw.Out = writerFunc(func(p []byte) (n int, err error) {
			return len(p), ew.elog.Error(1, string(p))
		})
	case zerolog.FatalLevel:
		ew.cw.Out = writerFunc(func(p []byte) (n int, err error) {
			return len(p), ew.elog.Error(2, string(p))
		})
	case zerolog.PanicLevel:
		ew.cw.Out = writerFunc(func(p []byte) (n int, err error) {
			return len(p), ew.elog.Error(3, string(p))
		})
	default:
		ew.cw.Out = writerFunc(func(p []byte) (n int, err error) {
			return len(p), ew.elog.Info(5, string(p))
		})
	}

	return ew.cw.Write(p)
}
