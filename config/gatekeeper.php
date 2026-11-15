<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | Authentication middleware
    |--------------------------------------------------------------------------
    | A route is in scope when one of its resolved middleware entries matches
    | one of these names, either exactly or as a "name:..." parameterised
    | entry. Public routes are skipped unless --include-public is passed.
    */
    'auth_middleware' => ['auth', 'auth.basic'],

    /*
    |--------------------------------------------------------------------------
    | Role-level middleware
    |--------------------------------------------------------------------------
    | These prove who a user is or which role they hold. They never prove the
    | user may touch the specific object named by a route parameter, so they
    | are recorded as role-level evidence and do not clear an object route.
    | The "can" middleware only clears a route when its second argument is
    | the route parameter itself, for example "can:update,invoice".
    */
    'role_middleware' => ['role', 'permission', 'role_or_permission', 'can'],

    /*
    |--------------------------------------------------------------------------
    | Permanent exceptions
    |--------------------------------------------------------------------------
    | URI prefixes and controller class names that are never reported.
    */
    'ignore_routes' => [],
    'ignore_controllers' => [],

    /*
    |--------------------------------------------------------------------------
    | Ownership
    |--------------------------------------------------------------------------
    | The unscoped-lookup rules only fire for models that belong to a user or
    | tenant. A model counts as owned when it is listed in "models", or when
    | its source shows a belongsTo relation or a relation method named in
    | "relations". "ignore_models" always wins. Models guarded by a global
    | scope are suppressed unless "flag_global_scopes" is true.
    */
    'ownership' => [
        'models' => [],
        'ignore_models' => [],
        'relations' => ['user', 'owner', 'tenant', 'team', 'account'],
        'columns' => ['user_id', 'owner_id', 'tenant_id', 'team_id', 'account_id'],
        'flag_global_scopes' => false,
        'global_scope_traits' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Baseline
    |--------------------------------------------------------------------------
    | Default baseline file, relative to the application base path. Findings
    | whose stable id is listed there are suppressed instead of reported.
    */
    'baseline' => 'gatekeeper-baseline.json',
];
