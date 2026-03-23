package slogredact

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func parseJSON(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("failed to parse JSON log: %v\nraw: %s", err, buf.String())
	}
	return m
}

func newTestLogger(buf *bytes.Buffer, opts ...Option) *slog.Logger {
	inner := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(New(inner, opts...))
}

func TestBasicRedaction(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)

	logger.Info("test", "username", "alice", "password", "secret123")

	m := parseJSON(t, &buf)
	if m["username"] != "alice" {
		t.Errorf("expected username=alice, got %v", m["username"])
	}
	if m["password"] != "[REDACTED]" {
		t.Errorf("expected password=[REDACTED], got %v", m["password"])
	}
}

func TestDefaultSensitiveKeys(t *testing.T) {
	keys := []struct {
		key   string
		value string
	}{
		{"password", "pass"},
		{"secret", "sec"},
		{"token", "tok"},
		{"api_key", "key"},
		{"apikey", "key"},
		{"authorization", "auth"},
		{"cookie", "cook"},
		{"session", "sess"},
		{"credit_card", "cc"},
		{"ssn", "123"},
		{"private_key", "pk"},
		{"access_token", "at"},
		{"refresh_token", "rt"},
	}

	for _, tc := range keys {
		var buf bytes.Buffer
		logger := newTestLogger(&buf)
		logger.Info("test", tc.key, tc.value)
		m := parseJSON(t, &buf)
		if m[tc.key] != "[REDACTED]" {
			t.Errorf("expected %s to be redacted, got %v", tc.key, m[tc.key])
		}
	}
}

func TestCaseInsensitive(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	logger.Info("test", "Password", "secret", "TOKEN", "tok123")

	m := parseJSON(t, &buf)
	if m["Password"] != "[REDACTED]" {
		t.Errorf("expected Password to be redacted, got %v", m["Password"])
	}
	if m["TOKEN"] != "[REDACTED]" {
		t.Errorf("expected TOKEN to be redacted, got %v", m["TOKEN"])
	}
}

func TestNonSensitivePassThrough(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	logger.Info("test", "username", "alice", "count", 42)

	m := parseJSON(t, &buf)
	if m["username"] != "alice" {
		t.Errorf("expected username=alice, got %v", m["username"])
	}
	if m["count"] != float64(42) {
		t.Errorf("expected count=42, got %v", m["count"])
	}
}

func TestGroupRedaction(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	logger.Info("test", slog.Group("user",
		slog.String("name", "alice"),
		slog.String("password", "secret123"),
	))

	m := parseJSON(t, &buf)
	group, ok := m["user"].(map[string]any)
	if !ok {
		t.Fatalf("expected user group, got %v", m["user"])
	}
	if group["name"] != "alice" {
		t.Errorf("expected name=alice, got %v", group["name"])
	}
	if group["password"] != "[REDACTED]" {
		t.Errorf("expected password=[REDACTED], got %v", group["password"])
	}
}

func TestWithSensitiveKeys(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, WithSensitiveKeys("custom_field"))
	logger.Info("test", "custom_field", "secret", "password", "visible")

	m := parseJSON(t, &buf)
	if m["custom_field"] != "[REDACTED]" {
		t.Errorf("expected custom_field redacted, got %v", m["custom_field"])
	}
	// password should NOT be redacted since we replaced the default keys
	if m["password"] != "visible" {
		t.Errorf("expected password=visible (not in custom keys), got %v", m["password"])
	}
}

func TestWithAdditionalKeys(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, WithAdditionalKeys("custom_field"))
	logger.Info("test", "custom_field", "secret", "password", "pass123")

	m := parseJSON(t, &buf)
	if m["custom_field"] != "[REDACTED]" {
		t.Errorf("expected custom_field redacted, got %v", m["custom_field"])
	}
	// password should still be redacted (default keys preserved)
	if m["password"] != "[REDACTED]" {
		t.Errorf("expected password redacted, got %v", m["password"])
	}
}

func TestWithAttrsRedaction(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	handler := New(inner)
	logger := slog.New(handler).With("token", "my-secret-token", "user", "alice")
	logger.Info("request")

	m := parseJSON(t, &buf)
	if m["token"] != "[REDACTED]" {
		t.Errorf("expected pre-added token redacted, got %v", m["token"])
	}
	if m["user"] != "alice" {
		t.Errorf("expected user=alice, got %v", m["user"])
	}
}

func TestEnabled(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	handler := New(inner)

	if handler.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("expected debug to be disabled")
	}
	if !handler.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("expected warn to be enabled")
	}
}

func TestWithGroup(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	handler := New(inner)
	logger := slog.New(handler.WithGroup("request"))
	logger.Info("test", "password", "secret")

	m := parseJSON(t, &buf)
	group, ok := m["request"].(map[string]any)
	if !ok {
		t.Fatalf("expected request group, got %v", m["request"])
	}
	if group["password"] != "[REDACTED]" {
		t.Errorf("expected password redacted in group, got %v", group["password"])
	}
}

type sensitiveData struct {
	secret string
}

func (s sensitiveData) LogValue() slog.Value {
	return slog.StringValue(s.secret)
}

func TestWithRedactedValue(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, WithRedactedValue("***"))
	logger.Info("test", "password", "secret123", "username", "alice")

	m := parseJSON(t, &buf)
	if m["password"] != "***" {
		t.Errorf("expected password='***', got %v", m["password"])
	}
	if m["username"] != "alice" {
		t.Errorf("expected username=alice, got %v", m["username"])
	}
}

func TestWithRedactedValueInGroup(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, WithRedactedValue("<hidden>"))
	logger.Info("test", slog.Group("auth",
		slog.String("token", "abc123"),
		slog.String("user", "bob"),
	))

	m := parseJSON(t, &buf)
	group, ok := m["auth"].(map[string]any)
	if !ok {
		t.Fatalf("expected auth group, got %v", m["auth"])
	}
	if group["token"] != "<hidden>" {
		t.Errorf("expected token='<hidden>' in group, got %v", group["token"])
	}
	if group["user"] != "bob" {
		t.Errorf("expected user=bob, got %v", group["user"])
	}
}

func TestDeepNestedGroupRedaction(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	logger.Info("test", slog.Group("level1",
		slog.Group("level2",
			slog.Group("level3",
				slog.String("password", "deep-secret"),
				slog.String("name", "test"),
			),
		),
	))

	m := parseJSON(t, &buf)
	l1, _ := m["level1"].(map[string]any)
	l2, _ := l1["level2"].(map[string]any)
	l3, _ := l2["level3"].(map[string]any)
	if l3["password"] != "[REDACTED]" {
		t.Errorf("expected deeply nested password redacted, got %v", l3["password"])
	}
	if l3["name"] != "test" {
		t.Errorf("expected name=test, got %v", l3["name"])
	}
}

func TestLogValuerResolved(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	logger.Info("test", "token", sensitiveData{secret: "my-raw-secret"})

	m := parseJSON(t, &buf)
	if m["token"] != "[REDACTED]" {
		t.Errorf("expected token with LogValuer to be redacted, got %v", m["token"])
	}
}

// --- Pattern matching tests ---

func TestWithPatterns(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf,
		WithSensitiveKeys(), // clear defaults
		WithPatterns(`^x-.*-key$`, `_secret$`),
	)
	logger.Info("test",
		"x-api-key", "key123",
		"x-auth-key", "auth456",
		"db_secret", "dbpass",
		"username", "alice",
	)

	m := parseJSON(t, &buf)
	if m["x-api-key"] != "[REDACTED]" {
		t.Errorf("expected x-api-key redacted, got %v", m["x-api-key"])
	}
	if m["x-auth-key"] != "[REDACTED]" {
		t.Errorf("expected x-auth-key redacted, got %v", m["x-auth-key"])
	}
	if m["db_secret"] != "[REDACTED]" {
		t.Errorf("expected db_secret redacted, got %v", m["db_secret"])
	}
	if m["username"] != "alice" {
		t.Errorf("expected username=alice, got %v", m["username"])
	}
}

func TestWithPatternsAndDefaults(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, WithPatterns(`_id$`))
	logger.Info("test",
		"user_id", "12345",
		"password", "secret",
		"name", "alice",
	)

	m := parseJSON(t, &buf)
	if m["user_id"] != "[REDACTED]" {
		t.Errorf("expected user_id redacted by pattern, got %v", m["user_id"])
	}
	if m["password"] != "[REDACTED]" {
		t.Errorf("expected password redacted by default keys, got %v", m["password"])
	}
	if m["name"] != "alice" {
		t.Errorf("expected name=alice, got %v", m["name"])
	}
}

func TestWithPatternsInvalidRegex(t *testing.T) {
	// Invalid patterns should be silently skipped
	var buf bytes.Buffer
	logger := newTestLogger(&buf,
		WithSensitiveKeys(),
		WithPatterns(`[invalid`, `_key$`),
	)
	logger.Info("test", "api_key", "val1", "name", "alice")

	m := parseJSON(t, &buf)
	if m["api_key"] != "[REDACTED]" {
		t.Errorf("expected api_key redacted by valid pattern, got %v", m["api_key"])
	}
	if m["name"] != "alice" {
		t.Errorf("expected name=alice, got %v", m["name"])
	}
}

// --- Custom mask function tests ---

func TestWithMask(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, WithMask(func(s string) string {
		return "MASKED:" + s
	}))
	logger.Info("test", "password", "secret123", "username", "alice")

	m := parseJSON(t, &buf)
	if m["password"] != "MASKED:secret123" {
		t.Errorf("expected password='MASKED:secret123', got %v", m["password"])
	}
	if m["username"] != "alice" {
		t.Errorf("expected username=alice, got %v", m["username"])
	}
}

func TestWithMaskOverridesRedactedValue(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf,
		WithRedactedValue("***"),
		WithMask(func(s string) string {
			return "custom"
		}),
	)
	logger.Info("test", "password", "secret")

	m := parseJSON(t, &buf)
	// mask function should take precedence over redacted value
	if m["password"] != "custom" {
		t.Errorf("expected password='custom', got %v", m["password"])
	}
}

func TestWithMaskInGroup(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, WithMask(PartialMask(4)))
	logger.Info("test", slog.Group("auth",
		slog.String("token", "abcdefghij"),
		slog.String("user", "bob"),
	))

	m := parseJSON(t, &buf)
	group, ok := m["auth"].(map[string]any)
	if !ok {
		t.Fatalf("expected auth group, got %v", m["auth"])
	}
	if group["token"] != "******ghij" {
		t.Errorf("expected token='******ghij', got %v", group["token"])
	}
	if group["user"] != "bob" {
		t.Errorf("expected user=bob, got %v", group["user"])
	}
}

// --- Value-based redaction tests ---

func TestWithValueRedaction(t *testing.T) {
	// Redact any value that looks like a credit card (simple check: 16 digits)
	isCreditCard := func(key string, val slog.Value) bool {
		s := val.String()
		if len(s) != 16 {
			return false
		}
		for _, c := range s {
			if c < '0' || c > '9' {
				return false
			}
		}
		return true
	}

	var buf bytes.Buffer
	logger := newTestLogger(&buf,
		WithSensitiveKeys(), // clear defaults
		WithValueRedaction(isCreditCard),
	)
	logger.Info("test",
		"card_number", "1234567890123456",
		"name", "alice",
		"short", "1234",
	)

	m := parseJSON(t, &buf)
	if m["card_number"] != "[REDACTED]" {
		t.Errorf("expected card_number redacted, got %v", m["card_number"])
	}
	if m["name"] != "alice" {
		t.Errorf("expected name=alice, got %v", m["name"])
	}
	if m["short"] != "1234" {
		t.Errorf("expected short=1234, got %v", m["short"])
	}
}

func TestWithValueRedactionAndMask(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf,
		WithSensitiveKeys(),
		WithValueRedaction(func(key string, val slog.Value) bool {
			return len(val.String()) > 10
		}),
		WithMask(PartialMask(4)),
	)
	logger.Info("test",
		"data", "abcdefghijklmnop",
		"short", "abc",
	)

	m := parseJSON(t, &buf)
	if m["data"] != "************mnop" {
		t.Errorf("expected data='************mnop', got %v", m["data"])
	}
	if m["short"] != "abc" {
		t.Errorf("expected short=abc, got %v", m["short"])
	}
}

func TestWithValueRedactionKeySpecific(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf,
		WithSensitiveKeys(),
		WithValueRedaction(func(key string, val slog.Value) bool {
			return key == "email" && strings.Contains(val.String(), "@")
		}),
	)
	logger.Info("test",
		"email", "alice@example.com",
		"note", "contact alice@example.com",
	)

	m := parseJSON(t, &buf)
	if m["email"] != "[REDACTED]" {
		t.Errorf("expected email redacted, got %v", m["email"])
	}
	// note should NOT be redacted since key != "email"
	if m["note"] != "contact alice@example.com" {
		t.Errorf("expected note unchanged, got %v", m["note"])
	}
}

// --- PartialMask tests ---

func TestPartialMask(t *testing.T) {
	mask := PartialMask(4)

	tests := []struct {
		input    string
		expected string
	}{
		{"1234567890", "******7890"},
		{"abcd", "abcd"},       // exactly showLast chars
		{"abc", "abc"},         // fewer than showLast chars
		{"12345", "*2345"},     // one more than showLast
		{"a", "a"},             // single char
		{"", ""},               // empty string
	}

	for _, tc := range tests {
		got := mask(tc.input)
		if got != tc.expected {
			t.Errorf("PartialMask(4)(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestPartialMaskZero(t *testing.T) {
	mask := PartialMask(0)
	got := mask("secret")
	if got != "******" {
		t.Errorf("PartialMask(0)(\"secret\") = %q, want %q", got, "******")
	}
}

func TestPartialMaskNegative(t *testing.T) {
	mask := PartialMask(-1)
	got := mask("secret")
	if got != "******" {
		t.Errorf("PartialMask(-1)(\"secret\") = %q, want %q", got, "******")
	}
}

// --- Stats tests ---

func TestStatsInitiallyZero(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	handler := New(inner)

	stats := handler.Stats()
	if stats.RedactedCount != 0 {
		t.Errorf("expected initial RedactedCount=0, got %d", stats.RedactedCount)
	}
}

func TestStatsCountsRedactions(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	handler := New(inner)
	logger := slog.New(handler)

	logger.Info("test", "password", "secret", "token", "tok123", "name", "alice")

	stats := handler.Stats()
	if stats.RedactedCount != 2 {
		t.Errorf("expected RedactedCount=2, got %d", stats.RedactedCount)
	}
}

func TestStatsAccumulatesAcrossLogs(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	handler := New(inner)
	logger := slog.New(handler)

	logger.Info("first", "password", "pass1")
	buf.Reset()
	logger.Info("second", "token", "tok1", "secret", "sec1")

	stats := handler.Stats()
	if stats.RedactedCount != 3 {
		t.Errorf("expected RedactedCount=3, got %d", stats.RedactedCount)
	}
}

func TestStatsSharedAcrossWithGroup(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	handler := New(inner)
	grouped := handler.WithGroup("req")
	logger := slog.New(grouped)

	logger.Info("test", "password", "secret")

	stats := handler.Stats()
	if stats.RedactedCount != 1 {
		t.Errorf("expected RedactedCount=1 shared via WithGroup, got %d", stats.RedactedCount)
	}
}

func TestStatsCountsPatternRedactions(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	handler := New(inner,
		WithSensitiveKeys(),
		WithPatterns(`_key$`),
	)
	logger := slog.New(handler)

	logger.Info("test", "api_key", "val1", "auth_key", "val2", "name", "alice")

	stats := handler.Stats()
	if stats.RedactedCount != 2 {
		t.Errorf("expected RedactedCount=2 for pattern redactions, got %d", stats.RedactedCount)
	}
}

func TestStatsCountsValueRedactions(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, nil)
	handler := New(inner,
		WithSensitiveKeys(),
		WithValueRedaction(func(key string, val slog.Value) bool {
			return val.String() == "sensitive"
		}),
	)
	logger := slog.New(handler)

	logger.Info("test", "a", "sensitive", "b", "safe", "c", "sensitive")

	stats := handler.Stats()
	if stats.RedactedCount != 2 {
		t.Errorf("expected RedactedCount=2 for value redactions, got %d", stats.RedactedCount)
	}
}
