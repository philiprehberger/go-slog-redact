# go-slog-redact

[![CI](https://github.com/philiprehberger/go-slog-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/go-slog-redact/actions/workflows/ci.yml) [![Go Reference](https://pkg.go.dev/badge/github.com/philiprehberger/go-slog-redact.svg)](https://pkg.go.dev/github.com/philiprehberger/go-slog-redact) [![License](https://img.shields.io/github/license/philiprehberger/go-slog-redact)](LICENSE)

Sensitive field redaction middleware for Go's `log/slog`

## Installation

```bash
go get github.com/philiprehberger/go-slog-redact
```

## Usage

### Basic Setup

```go
import "github.com/philiprehberger/go-slog-redact"

jsonHandler := slog.NewJSONHandler(os.Stdout, nil)
redactHandler := slogredact.New(jsonHandler)
logger := slog.New(redactHandler)

logger.Info("user login",
    "username", "alice",
    "password", "secret123",
    "token", "abc-xyz",
)
// Output: {"username":"alice","password":"[REDACTED]","token":"[REDACTED]"}
```

### Default Sensitive Keys

The following keys are redacted by default:
`password`, `secret`, `token`, `api_key`, `apikey`, `authorization`, `cookie`, `session`, `credit_card`, `ssn`, `private_key`, `access_token`, `refresh_token`

### Custom Sensitive Keys

```go
handler := slogredact.New(inner,
    slogredact.WithSensitiveKeys("password", "ssn", "my_custom_field"),
)
```

### Custom Redaction String

```go
handler := slogredact.New(inner,
    slogredact.WithRedactedValue("***"),
)
// Sensitive fields will show "***" instead of "[REDACTED]"
```

### Add to Default List

```go
handler := slogredact.New(inner,
    slogredact.WithAdditionalKeys("stripe_key", "database_url"),
)
```

### Works with Groups

```go
logger.WithGroup("request").Info("incoming",
    "path", "/api/users",
    "authorization", "Bearer xxx",
)
// authorization is still redacted inside groups
```

## API

| Function / Method | Description |
|---|---|
| `Handler` | slog.Handler middleware that redacts sensitive fields |
| `Option` | Functional option for configuring the handler |
| `New(inner slog.Handler, opts ...Option) *Handler` | Create a new redacting handler |
| `WithSensitiveKeys(keys ...string) Option` | Replace the default sensitive keys list |
| `WithAdditionalKeys(keys ...string) Option` | Add keys to the default sensitive list |
| `WithRedactedValue(s string) Option` | Set custom replacement string (default "[REDACTED]") |
| `(*Handler) Enabled(ctx, level) bool` | Report whether the inner handler handles this level |
| `(*Handler) Handle(ctx, record) error` | Redact sensitive fields and delegate to inner handler |
| `(*Handler) WithAttrs(attrs []slog.Attr) slog.Handler` | Return handler with pre-added redacted attributes |
| `(*Handler) WithGroup(name string) slog.Handler` | Return handler scoped to a group |
| `DefaultSensitiveKeys` | Default list of field names redacted automatically |

## Development

```bash
go test ./...
go vet ./...
```

## License

MIT
