# go-slog-redact

[![CI](https://github.com/philiprehberger/go-slog-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/go-slog-redact/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/philiprehberger/go-slog-redact.svg)](https://pkg.go.dev/github.com/philiprehberger/go-slog-redact)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/go-slog-redact)](https://github.com/philiprehberger/go-slog-redact/commits/main)

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

### Pattern Redaction

Redact keys matching regex patterns instead of listing every key name:

```go
handler := slogredact.New(inner,
    slogredact.WithPatterns(`_key$`, `^x-.*-token$`),
)
logger := slog.New(handler)

logger.Info("request",
    "api_key", "sk-123",        // redacted (matches _key$)
    "x-auth-token", "tok-456",  // redacted (matches ^x-.*-token$)
    "username", "alice",        // not redacted
)
```

### Custom Masking

Replace the default `[REDACTED]` string with a custom masking function:

```go
handler := slogredact.New(inner,
    slogredact.WithMask(slogredact.PartialMask(4)),
)
logger := slog.New(handler)

logger.Info("payment", "credit_card", "4111111111111111")
// Output: credit_card="************1111"
```

The built-in `PartialMask(n)` helper shows only the last `n` characters, replacing the rest with asterisks. You can also provide any `func(string) string`:

```go
handler := slogredact.New(inner,
    slogredact.WithMask(func(s string) string {
        return "[HIDDEN:" + strconv.Itoa(len(s)) + " chars]"
    }),
)
```

### Value-Based Redaction

Redact fields based on their value content rather than key name:

```go
handler := slogredact.New(inner,
    slogredact.WithValueRedaction(func(key string, val slog.Value) bool {
        // Redact any value that looks like a credit card number
        s := val.String()
        return len(s) == 16 && isAllDigits(s)
    }),
)
```

### Stats

Track how many values have been redacted:

```go
handler := slogredact.New(inner)
logger := slog.New(handler)

logger.Info("login", "password", "secret", "token", "abc")
stats := handler.Stats()
fmt.Println(stats.RedactedCount) // 2
```

Stats are accumulated atomically and shared across handlers created via `WithGroup` and `WithAttrs`.

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
| `RedactStats` | Struct holding redaction statistics (`RedactedCount int64`) |
| `New(inner slog.Handler, opts ...Option) *Handler` | Create a new redacting handler |
| `WithSensitiveKeys(keys ...string) Option` | Replace the default sensitive keys list |
| `WithAdditionalKeys(keys ...string) Option` | Add keys to the default sensitive list |
| `WithRedactedValue(s string) Option` | Set custom replacement string (default "[REDACTED]") |
| `WithPatterns(patterns ...string) Option` | Redact keys matching regex patterns |
| `WithMask(fn func(string) string) Option` | Custom masking function instead of fixed string |
| `WithValueRedaction(pred func(string, slog.Value) bool) Option` | Redact based on value content |
| `PartialMask(showLast int) func(string) string` | Masking function showing only the last N characters |
| `(*Handler) Enabled(ctx, level) bool` | Report whether the inner handler handles this level |
| `(*Handler) Handle(ctx, record) error` | Redact sensitive fields and delegate to inner handler |
| `(*Handler) WithAttrs(attrs []slog.Attr) slog.Handler` | Return handler with pre-added redacted attributes |
| `(*Handler) WithGroup(name string) slog.Handler` | Return handler scoped to a group |
| `(*Handler) Stats() RedactStats` | Return current redaction statistics |
| `DefaultSensitiveKeys` | Default list of field names redacted automatically |

## Development

```bash
go test ./...
go vet ./...
```

## Support

If you find this project useful:

⭐ [Star the repo](https://github.com/philiprehberger/go-slog-redact)

🐛 [Report issues](https://github.com/philiprehberger/go-slog-redact/issues?q=is%3Aissue+is%3Aopen+label%3Abug)

💡 [Suggest features](https://github.com/philiprehberger/go-slog-redact/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)

❤️ [Sponsor development](https://github.com/sponsors/philiprehberger)

🌐 [All Open Source Projects](https://philiprehberger.com/open-source-packages)

💻 [GitHub Profile](https://github.com/philiprehberger)

🔗 [LinkedIn Profile](https://www.linkedin.com/in/philiprehberger)

## License

[MIT](LICENSE)
