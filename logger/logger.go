package logger

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/middleware"

	"github.com/sirupsen/logrus"
)

type UTCFormatter struct{ logrus.Formatter }

func (u UTCFormatter) Format(e *logrus.Entry) ([]byte, error) {
	e.Time = e.Time.UTC()
	return u.Formatter.Format(e)
}

type BufferedFormatter struct {
	q []*logrus.Entry
}

func (b *BufferedFormatter) Format(e *logrus.Entry) ([]byte, error) {
	if b.q == nil {
		b.q = make([]*logrus.Entry, 0, 30)
	}
	b.q = append(b.q, e)
	return nil, nil
}

// set or change the formatter for the given logger, to either text or JSON format.
// if the current formatter for the logger is a buffered log, then the buffered log lines are flushed, according to the new format
func SetFormat(log *logrus.Logger, useJSON bool) {
	var q []*logrus.Entry
	if f, ok := log.Formatter.(*BufferedFormatter); ok {
		q = f.q
	}
	if useJSON {
		log.Formatter = UTCFormatter{&logrus.JSONFormatter{
			TimestampFormat: time.RFC1123,
		}}
	} else {
		log.Formatter = UTCFormatter{&logrus.TextFormatter{
			TimestampFormat:  time.RFC1123,
			QuoteEmptyFields: true,
		}}
	}
	for _, e := range q {
		// process the entry
		ftd, err := log.Formatter.Format(e)
		if err != nil {
			continue // do we really want to log.. an error logging?
		}
		fmt.Fprint(log.Out, string(ftd))
	}
}

// Create a logrus instance, where log entries are buffered in memory until SetFormat() is called. Once it is called, the buffered entries are flushed and printed in the given format.
func NewBuffered() *logrus.Logger {
	log := logrus.New()
	log.Formatter = &BufferedFormatter{}
	return log
}

// Create a general-purpose logrus logger, either in JSON or text format depending on the argument.
func New(json bool) *logrus.Logger {
	log := logrus.New()
	SetFormat(log, json)
	return log
}

/* --- Chi-specific setup ---- */

type ChiLogger struct{ l *logrus.Logger }

// uses a logrus logger instance as a Chi Middleware logger
func NewChi(log *logrus.Logger) *ChiLogger {
	return &ChiLogger{log}
}

func (cl *ChiLogger) NewLogEntry(r *http.Request) middleware.LogEntry {
	scheme := "http"
	if r.TLS != nil {
		scheme += "s"
	}

	entry := &ChiLogEntry{logrus.NewEntry(cl.l)}
	pf := logrus.Fields{
		"remote_addr": r.RemoteAddr,
		"user_agent":  r.UserAgent(),
		"uri":         fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI),
	}
	if reqID := middleware.GetReqID(r.Context()); reqID != "" {
		pf["reqID"] = reqID
	}

	entry.l = entry.l.WithFields(pf)
	entry.l.WithFields(logrus.Fields{
		"http_scheme": scheme,
		"http_proto":  r.Proto,
		"http_method": r.Method,
		"headers":     r.Header,
	}).Infoln("request started")

	return entry
}

func (cl *ChiLogger) L() *logrus.Logger { return cl.l }

type ChiLogEntry struct {
	l logrus.FieldLogger
}

func (cle *ChiLogEntry) Write(status int, bytes int, elapsed time.Duration) {
	cle.l = cle.l.WithFields(logrus.Fields{
		"resp_status":     status,
		"resp_bytes_len":  bytes,
		"resp_elapsed_ms": float64(elapsed.Nanoseconds()) / 1000000.0,
	})
	cle.l.Infoln("request complete")
}

func (cle *ChiLogEntry) Panic(v interface{}, stack []byte) {
	cle.l = cle.l.WithFields(logrus.Fields{
		"stack": string(stack),
		"panic": fmt.Sprintf("%+v", v),
	})
}

/* --- handler log -setter helper -----*/

// In an HTTP-handler context, call logger.GetLog(r) to get the logger instance to use
func GetLog(r *http.Request) logrus.FieldLogger {
	entry := middleware.GetLogEntry(r)
	if entry != nil {
		if e, ok := entry.(*ChiLogEntry); ok {
			return e.l
		}
	}
	return logrus.StandardLogger()
}

func LogFromCtx(ctx context.Context) logrus.FieldLogger {
	if entry, ok := ctx.Value(middleware.LogEntryCtxKey).(*ChiLogEntry); ok {
		return entry.l
	}
	return logrus.StandardLogger()
}

func Log(r *http.Request, key string, value interface{}) {
	if entry, ok := r.Context().Value(middleware.LogEntryCtxKey).(*ChiLogEntry); ok {
		entry.l = entry.l.WithField(key, value)
	}
}
