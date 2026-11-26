# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking changes

- Rewritten on the official
  [Sign in with ChatGPT plan usage](https://developers.openai.com/siwc/token-sharing-open-source)
  flow; the Codex CLI client ID and the WHAM backend are no longer used.
- New `auth.json` format; run `login` again (an old file is moved to `auth.json.old`).
- `login` prints the sign-in URL and asks you to paste the redirected URL instead of opening a browser.
- `list` no longer writes `models.json`.

### Added

- `logout` and `login --consent` commands.
- `test --prompt` and `test --effort`; `test` defaults to the last listed model and prints the request's token usage.
- `SPEC.md` (rules taken from the official documentation).

## [0.0.1] - 2026-03-01

- Initial sample using the Codex CLI client ID and the WHAM backend.
