# Changelog

All notable changes to Gatekeeper Audit are documented here.

## 1.0.2 - 2026-11-15

- Added a coverage section to the console summary, verbose output, JSON report, and markdown report. It lists the files the audit opened, groups skipped routes by reason, and counts routes by the file that registered them, including custom route file names. Application console commands are listed and not audited.

## 1.0.1 - 2026-11-15

- Colored the console report and added a suggested diff for each finding. Added lines are green and removed lines are red.
- Added `--format=markdown` and `--output` so an agent can read one fix list. `patch` means apply the diff as written. `hint` means adapt it first.
- Added the same suggestion to the JSON report. The audit still does not edit application code.
- Kept suggested diffs inside the action. An assigned lookup is rewritten in place, a closure body receives the authorize call, and a lookup that cannot be rewritten is left unchanged.

## 1.0.0 - 2026-11-14

- Added `gatekeeper:audit`, which boots the application, reads the registered route table, and reports authenticated object routes with no object-level authorization check.
- Added checks for `can` middleware targets, `authorizeResource`, `HasMiddleware`, FormRequest `authorize()` methods, and policies that only return `true`.
- Added unscoped lookup and collection rules for owned models, with global scope suppression and scoped binding awareness.
- Added console, JSON, GitHub, and SARIF reports, `--fail-on-unauthorized`, severity thresholds, and exit codes for CI.
- Added `gatekeeper:baseline` and `--prune-baseline` so existing applications can record current findings and fail on new ones.
