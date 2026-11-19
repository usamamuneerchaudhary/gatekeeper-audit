# Changelog

All notable changes to Gatekeeper Audit are documented here.

## 1.0.3 - Unreleased

This release fixes checks that let insecure routes pass. Expect more findings than 1.0.2 on the same code: those routes were missed before. Review them before you refresh a baseline.

### Fixed: routes reported as authorized when they were not

- Evidence and suggestions printed `PhpParser\Node\Expr\MethodCall` instead of source code, because the printer call did not exist in php-parser 5. Checks that read that text also failed. A FormRequest `authorize()` that returns `auth()->check()` or `$this->user() !== null` is now reported as `trivial_form_request`, as documented. A guard clause such as `if (! $this->user()) { return false; }` before `return true` is reported too.
- Lookups on a model that uses `SoftDeletes` were suppressed as globally scoped. Framework scopes no longer count as owner or tenant scopes.
- `HasMiddleware` middleware declared with `only:` cleared every action of the controller. Route middleware is now read only from Laravel's resolved middleware list, which applies `only` and `except`.
- A `can()`, `Gate::allows()`, or `Gate::denies()` result that was assigned, passed to a view, or discarded cleared the route. The result must now decide the request: a condition, `abort_if` or `abort_unless`, or the return value of a helper the action calls. Unused results appear as evidence.
- A FormRequest that only read the route model, such as `return $this->route('invoice') !== null;`, or called `$this->route()` with no argument, counted as an object-level check. The model must now reach an ability call or be compared with the signed-in user.
- Arrow function routes were matched to the first closure in the file, usually the route group, so a sibling route's gate call cleared them. Closures and arrow functions are now matched by line, and an unmatched closure is reported as `unparsed_action`.
- `Auth::check()` and `auth()->check()` counted as authorization and hid `missing_authorization`.
- `Model::destroy($id)`, `firstWhere`, `findMany`, `findOr`, `updateOrCreate`, `firstOrNew`, and chained writes such as `where('id', $id)->update()` and `->delete()` were not checked.
- A `user()` call anywhere in a query, including an unrelated constraint, marked the query as scoped. Only the query's own call chain, or an owner column compared with the signed-in user, the current tenant, or a route-bound model, now scopes it.
- `DB::table()` queries skipped the scoping check, and were only checked when the table matched a route-bound model. They are now scoped like Eloquent queries, and the table is also matched against `ownership.models` and the conventional `App\Models` class.

### Fixed: false positives

- `$this->invoice` in a FormRequest is recognised as the routed model.
- `where('user_id', Auth::id())` is recognised as scoped.

### Fixed: command and reports

- `--prune-baseline` wrote every current finding into the baseline, so new findings were hidden and the run passed. It now only removes ids that are no longer reported. It refuses to run with `--only`, which would have dropped every id outside the prefix. It exits with `2` when there is no baseline to prune.
- `--fail-on-unauthorized` now includes `missing_authorization`, as documented.
- Finding paths are relative to the application base path in every format, so GitHub annotations attach to files in pull requests. SARIF locations carry `uriBaseId: %SRCROOT%`, and paths outside the application become `file://` URIs.
- GitHub annotation messages no longer show `%3A` and `%2C` in place of colons and commas.

### Internal

- Added PHPStan at level 6 to CI through Slipway, plus `composer analyse`. PHPStan reports the missing printer method in 1.0.2.
- Added regression tests for each fix above.
- Removed unused code: route binder sniffing, the unused model inspector dependency of the action inspector, and the command's second baseline pass.
- `SECURITY.md` now states that the audit boots the application and may construct controllers, policies, and commands.

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
