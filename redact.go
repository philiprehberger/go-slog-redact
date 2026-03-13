// Package slogredact provides a slog.Handler middleware that redacts sensitive fields.
package slogredact

import (
	"context"
	"log/slog"
	"strings"
)

const defaultRedactedValue = "[REDACTED]"

// DefaultSensitiveKeys are field names that are redacted by default.
var DefaultSensitiveKeys = []string{
	"password", "secret", "token", "api_key", "apikey",
	"authorization", "cookie", "session", "credit_card",
	"ssn", "private_key", "access_token", "refresh_token",
}

// Handler wraps a slog.Handler and redacts sensitive fields from log records.
type Handler struct {
	inner         slog.Handler
	sensitiveKeys map[string]struct{}
	redactedValue string
	attrs         []slog.Attr
	groups        []string
}

// Option configures a Handler.
type Option func(*Handler)

// WithSensitiveKeys sets the sensitive keys to redact.
// This replaces the default list.
func WithSensitiveKeys(keys ...string) Option {
	return func(h *Handler) {
		h.sensitiveKeys = make(map[string]struct{}, len(keys))
		for _, k := range keys {
			h.sensitiveKeys[strings.ToLower(k)] = struct{}{}
		}
	}
}

// WithAdditionalKeys adds sensitive keys to the default list.
func WithAdditionalKeys(keys ...string) Option {
	return func(h *Handler) {
		for _, k := range keys {
			h.sensitiveKeys[strings.ToLower(k)] = struct{}{}
		}
	}
}

// WithRedactedValue sets the string used to replace sensitive values.
// Defaults to "[REDACTED]".
func WithRedactedValue(s string) Option {
	return func(h *Handler) {
		h.redactedValue = s
	}
}

// New creates a new redacting Handler wrapping the given inner handler.
func New(inner slog.Handler, opts ...Option) *Handler {
	h := &Handler{
		inner:         inner,
		sensitiveKeys: make(map[string]struct{}, len(DefaultSensitiveKeys)),
		redactedValue: defaultRedactedValue,
	}
	for _, k := range DefaultSensitiveKeys {
		h.sensitiveKeys[strings.ToLower(k)] = struct{}{}
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Enabled reports whether the inner handler handles records at the given level.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle redacts sensitive fields before delegating to the inner handler.
func (h *Handler) Handle(ctx context.Context, record slog.Record) error {
	newRecord := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)

	// Add pre-added attrs
	for _, a := range h.attrs {
		newRecord.AddAttrs(h.redactAttr(a))
	}

	record.Attrs(func(a slog.Attr) bool {
		newRecord.AddAttrs(h.redactAttr(a))
		return true
	})

	return h.inner.Handle(ctx, newRecord)
}

// WithAttrs returns a new Handler with the given attributes pre-added (after redaction).
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = h.redactAttr(a)
	}
	newAttrs := make([]slog.Attr, len(h.attrs)+len(redacted))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], redacted)
	return &Handler{
		inner:         h.inner.WithAttrs(redacted),
		sensitiveKeys: h.sensitiveKeys,
		redactedValue: h.redactedValue,
		attrs:         newAttrs,
		groups:        h.groups,
	}
}

// WithGroup returns a new Handler with the given group name.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{
		inner:         h.inner.WithGroup(name),
		sensitiveKeys: h.sensitiveKeys,
		redactedValue: h.redactedValue,
		groups:        append(append([]string{}, h.groups...), name),
	}
}

func (h *Handler) redactAttr(a slog.Attr) slog.Attr {
	// Resolve LogValuer types before checking
	a.Value = a.Value.Resolve()

	// Handle groups recursively
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		redacted := make([]slog.Attr, len(attrs))
		for i, ga := range attrs {
			redacted[i] = h.redactAttr(ga)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(redacted...)}
	}

	if h.isSensitive(a.Key) {
		return slog.String(a.Key, h.redactedValue)
	}
	return a
}

func (h *Handler) isSensitive(key string) bool {
	_, ok := h.sensitiveKeys[strings.ToLower(key)]
	return ok
}
