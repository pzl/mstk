package mstk

/*
Default configs for chi middleware

And some common middlewares to use
*/

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/middleware"
	"github.com/pzl/mstk/logger"
	"github.com/sirupsen/logrus"
)

func DefaultMiddleware(log *logrus.Logger) []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{
		middleware.RealIP, // X-Forwarded-For
		middleware.RequestID,
		middleware.RequestLogger(logger.NewChi(log)),
		middleware.Heartbeat("/ping"),
		middleware.Recoverer,
		contentJSON,
	}
	//https://github.com/go-chi/chi#auxiliary-middlewares--packages
}

func contentJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		next.ServeHTTP(w, r)
	})
}

// middleware
func APIVer(ver int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(context.WithValue(r.Context(), "api.version", ver))
			next.ServeHTTP(w, r)
		})
	}
}

func NotFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("{\"error\":\"not found\"}")) //nolint
}
