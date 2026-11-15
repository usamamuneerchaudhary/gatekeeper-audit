# Changelog

All notable changes to Gatekeeper Audit are documented here.

## 1.0.0 - 2026-11-14

- Added `gatekeeper:audit`, which boots the application, reads the registered route table, and reports authenticated object routes with no object-level authorization check.
- Added checks for `can` middleware targets, `authorizeResource`, `HasMiddleware`, FormRequest `authorize()` methods, and policies that only return `true`.
- Added unscoped lookup and collection rules for owned models, with global scope suppression and scoped binding awareness.
- Added console, JSON, GitHub, and SARIF reports, `--fail-on-unauthorized`, severity thresholds, and exit codes for CI.
- Added `gatekeeper:baseline` and `--prune-baseline` so existing applications can record current findings and fail on new ones.
