// Package slogredact provides a slog.Handler middleware that redacts sensitive fields.
package slogredact

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
	"sync/atomic"
)

const defaultRedactedValue = "[REDACTED]"

// DefaultSensitiveKeys are field names that are redacted by default.
var DefaultSensitiveKeys = []string{
	"password", "secret", "token", "api_key", "apikey",
	"authorization", "cookie", "session", "credit_card",
	"ssn", "private_key", "access_token", "refresh_token",
}

// RedactStats holds statistics about redaction operations.
type RedactStats struct {
	RedactedCount int64
}

// Handler wraps a slog.Handler and redacts sensitive fields from log records.
type Handler struct {
	inner          slog.Handler
	sensitiveKeys  map[string]struct{}
	redactedValue  string
	patterns       []*regexp.Regexp
	maskFn         func(string) string
	valuePredicate func(key string, val slog.Value) bool
	stats          *atomic.Int64
	attrs          []slog.Attr
	groups         []string
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

// WithPatterns adds regex patterns for matching sensitive key names.
// Keys that match any pattern are redacted. Patterns are compiled via regexp.Compile.
func WithPatterns(patterns ...string) Option {
	return func(h *Handler) {
		for _, p := range patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				continue
			}
			h.patterns = append(h.patterns, re)
		}
	}
}

// WithMask sets a custom masking function instead of the default "[REDACTED]" string.
// The function receives the original string value and returns the masked version.
func WithMask(fn func(string) string) Option {
	return func(h *Handler) {
		h.maskFn = fn
	}
}

// WithValueRedaction sets a predicate that decides whether to redact based on value content.
// When the predicate returns true for a given key and value, the value is redacted.
func WithValueRedaction(pred func(key string, val slog.Value) bool) Option {
	return func(h *Handler) {
		h.valuePredicate = pred
	}
}

// PartialMask returns a masking function that shows only the last n characters,
// replacing the rest with asterisks. For example, PartialMask(4) on "1234567890"
// returns "******7890".
func PartialMask(showLast int) func(string) string {
	return func(s string) string {
		if showLast <= 0 {
			return strings.Repeat("*", len(s))
		}
		if showLast >= len(s) {
			return s
		}
		masked := strings.Repeat("*", len(s)-showLast)
		return masked + s[len(s)-showLast:]
	}
}

// New creates a new redacting Handler wrapping the given inner handler.
func New(inner slog.Handler, opts ...Option) *Handler {
	h := &Handler{
		inner:         inner,
		sensitiveKeys: make(map[string]struct{}, len(DefaultSensitiveKeys)),
		redactedValue: defaultRedactedValue,
		stats:         &atomic.Int64{},
	}
	for _, k := range DefaultSensitiveKeys {
		h.sensitiveKeys[strings.ToLower(k)] = struct{}{}
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Stats returns the current redaction statistics.
func (h *Handler) Stats() RedactStats {
	return RedactStats{
		RedactedCount: h.stats.Load(),
	}
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
		inner:          h.inner.WithAttrs(redacted),
		sensitiveKeys:  h.sensitiveKeys,
		redactedValue:  h.redactedValue,
		patterns:       h.patterns,
		maskFn:         h.maskFn,
		valuePredicate: h.valuePredicate,
		stats:          h.stats,
		attrs:          newAttrs,
		groups:         h.groups,
	}
}

// WithGroup returns a new Handler with the given group name.
func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{
		inner:          h.inner.WithGroup(name),
		sensitiveKeys:  h.sensitiveKeys,
		redactedValue:  h.redactedValue,
		patterns:       h.patterns,
		maskFn:         h.maskFn,
		valuePredicate: h.valuePredicate,
		stats:          h.stats,
		groups:         append(append([]string{}, h.groups...), name),
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

	// Check key-based redaction (exact match or pattern match)
	if h.isSensitive(a.Key) {
		h.stats.Add(1)
		return slog.String(a.Key, h.maskValue(a.Value))
	}

	// Check value-based redaction
	if h.valuePredicate != nil && h.valuePredicate(a.Key, a.Value) {
		h.stats.Add(1)
		return slog.String(a.Key, h.maskValue(a.Value))
	}

	return a
}

// maskValue applies the mask function or falls back to the redacted value string.
func (h *Handler) maskValue(v slog.Value) string {
	if h.maskFn != nil {
		return h.maskFn(v.String())
	}
	return h.redactedValue
}

func (h *Handler) isSensitive(key string) bool {
	lower := strings.ToLower(key)
	if _, ok := h.sensitiveKeys[lower]; ok {
		return true
	}
	for _, re := range h.patterns {
		if re.MatchString(lower) {
			return true
		}
	}
	return false
}
