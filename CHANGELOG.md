# Changelog

## 0.4.1

- Standardize README to 3-badge format with emoji Support section
- Update CI checkout action to v5 for Node.js 24 compatibility
- Add GitHub issue templates, dependabot config, and PR template

## 0.4.0

- Add `WithPatterns()` option to redact keys matching regex patterns
- Add `WithMask()` option for custom masking functions instead of fixed redaction string
- Add `WithValueRedaction()` option to redact based on value content
- Add `PartialMask()` helper that returns a masking function showing only the last N characters
- Add `Stats()` method and `RedactStats` type for tracking redaction counts atomically

## 0.3.2

- Consolidate README badges onto single line

## 0.3.1

- Add badges and Development section to README

## 0.3.0

- Add `WithRedactedValue()` option to customize the replacement string (default: `[REDACTED]`)
- Add deep nested group redaction test

## 0.2.0

- Fix `WithAttrs` not preserving pre-added attributes for redaction
- Resolve `LogValuer` types before checking for sensitive keys
- Add comprehensive test suite

## 0.1.0

- Initial release
