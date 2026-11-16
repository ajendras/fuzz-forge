# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-16

### Added

- OpenAPI Import — Parses specs into executable test plans with endpoint semantics
- Local LLM Gen — Queries Ollama to craft targeted payloads that respect your schema
- Smart Mutations — Applies XSS, SQLi, IDOR, auth and logic mutators with context
- Async Runner — Executes tests in parallel while enforcing safe rate limits
- Rich Reports — HTML + JSON output with curl repro steps and risk scores
- Extensible — Simple base classes let you drop in custom mutators or detectors
- Safe Defaults — Dry-run mode, host allowlists and non-destructive actions only
- Replay Suite — Saves failing cases for regression testing in CI
