package slogredact

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
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

func TestLogValuerResolved(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf)
	logger.Info("test", "token", sensitiveData{secret: "my-raw-secret"})

	m := parseJSON(t, &buf)
	if m["token"] != "[REDACTED]" {
		t.Errorf("expected token with LogValuer to be redacted, got %v", m["token"])
	}
}
