# go-slog-redact

Sensitive field redaction middleware for Go's `log/slog`.

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

## License

MIT
