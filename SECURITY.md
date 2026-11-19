# Security Policy

Report vulnerabilities through the [GitHub security advisory](https://github.com/usamamuneerchaudhary/gatekeeper-audit/security/advisories/new) form rather than a public issue.

Include the affected version, a route and controller example that reproduces the problem, and the report output with any sensitive paths removed.

Gatekeeper Audit does not send telemetry or make network requests, and it does not edit application code. It writes a file only when you pass `--output`, or when the baseline commands write the baseline.

It is not a passive file reader. The audit boots your application the way `php artisan route:list` does, so service providers run. While it collects route middleware, Laravel may construct controllers that do not use the `HasMiddleware` contract. Resolving policies through the gate constructs policy classes, and listing console commands resolves them from the container. Any side effect in those constructors runs during the audit.

Run it with `APP_ENV=testing`, a throwaway database, and no production credentials, as the README's CI example does.
