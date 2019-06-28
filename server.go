package mstk

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/pzl/mstk/logger"
	"github.com/sirupsen/logrus"
)

type Cfg struct {
	SSLCert string
	SSLPKey string
	JSON    bool
	Listen  []string
}

type SrvOpt func(s *Server)

/*
http.Server with sane defaults,
able to listen on multiple nets,
and with optimal SSL config
*/
type Server struct {
	Http *http.Server
	Log  *logrus.Logger
	Cfg  *Cfg
}

func NewServer(opts ...SrvOpt) *Server {
	c := Cfg{ //defaults
		JSON:   false,
		Listen: []string{"tcp4", "tcp6"},
	}
	s := &Server{
		Cfg: &c,
		Http: &http.Server{
			Addr:           ":0",
			ReadTimeout:    5 * time.Second,
			WriteTimeout:   10 * time.Second,
			IdleTimeout:    120 * time.Second,
			MaxHeaderBytes: 1 << 20,
			TLSConfig:      TLSConfig(),
			TLSNextProto:   TLSNextProto(),
		},
	}
	for _, o := range opts {
		if o != nil {
			o(s)
		}
	}
	if s.Log == nil {
		s.Log = logger.New(c.JSON)
	}
	return s

}

func (s *Server) Start(ctx context.Context) (err error) {
	errs := make(chan error)
	for _, l := range s.Cfg.Listen {
		s.Log.WithField("transport", l).WithField("addr", s.Http.Addr).Debug("opening socket")
		n, err := net.Listen(l, s.Http.Addr)
		if err != nil {
			return err
		}
		go s.listen(n, s.Cfg.SSLCert, s.Cfg.SSLPKey, errs)
	}
	s.Log.Infof("listening on %s", s.Http.Addr)

	select {
	case err = <-errs:
	case <-ctx.Done():
	}
	if err != nil && err != http.ErrServerClosed {
		s.Log.WithError(err).Error("Http Server stopped unexpectedly")
		s.Shutdown(ctx)
	} else {
		s.Log.Info("server stopped")
	}
	return nil
}

func (s *Server) listen(l net.Listener, cert, key string, errs chan<- error) {
	if cert != "" && key != "" {
		errs <- s.Http.ServeTLS(l, cert, key)
	} else {
		errs <- s.Http.Serve(l)
	}
}

func (s *Server) Shutdown(ctx context.Context) {
	if s.Http != nil {
		err := s.Http.Shutdown(ctx)
		if err != nil {
			s.Log.WithError(err).Error("failed to shutdown http server gracefully")
		} else {
			s.Http = nil
		}
	}
}

// Usage: server.New(server.Addr("127.0.0.1:3333"))
func Addr(addr string) SrvOpt { return func(s *Server) { s.Http.Addr = addr } }

func SSL(cert string, key string) SrvOpt {
	return func(s *Server) {
		s.Cfg.SSLCert = cert
		s.Cfg.SSLPKey = key
	}
}

// https://gist.github.com/denji/12b3a568f092ab951456#perfect-ssl-labs-score-with-go
func TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
}

func TLSNextProto() map[string]func(*http.Server, *tls.Conn, http.Handler) {
	return make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0)
}
