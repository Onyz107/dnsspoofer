package logger

import (
	"context"

	"github.com/florianl/go-nfqueue/v2"
)

type Logger interface {
	nfqueue.Logger
	Debug(msg any, args ...any)
	Error(msg any, args ...any)
	Info(msg any, args ...any)
}

type ctxKey struct{}

// NopLogger satisfies the Logger interface.
type NopLogger struct{}

func WithLogger(ctx context.Context, l Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

func LoggerFrom(ctx context.Context) Logger {
	if l, ok := ctx.Value(ctxKey{}).(Logger); ok {
		return l
	}
	return new(NopLogger)
}
