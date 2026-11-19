<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\BinaryOp;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\NullsafePropertyFetch;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;

/**
 * Recognise expressions that read the authenticated user from the AST.
 *
 * These checks replace substring matching on printed source, which matched
 * unrelated code such as "author" or a user() call buried in an argument.
 */
final class AuthExpressions
{
    /**
     * Whether the expression is the authenticated user itself.
     *
     * Matches `$request->user()`, `$this->user()`, `auth()->user()`, `request()->user()`,
     * `Auth::user()`, `Auth::guard()->user()`, and their nullsafe forms.
     */
    public static function isUser(Node $node): bool
    {
        if ($node instanceof StaticCall) {
            return self::isAuthFacade($node->class) && self::named($node->name, ['user']);
        }

        if (! $node instanceof MethodCall && ! $node instanceof NullsafeMethodCall) {
            return false;
        }

        if (! self::named($node->name, ['user'])) {
            return false;
        }

        return self::isUserSource($node->var);
    }

    /**
     * Whether the expression is derived from the authenticated user.
     *
     * Matches `Auth::id()`, `auth()->id()`, and any property or method read on the
     * user such as `$request->user()->id` or `auth()->user()->currentTeam->id`.
     * A `tenant()` helper call also counts, because it reads the current tenant.
     */
    public static function isUserDerived(Node $node): bool
    {
        $current = $node;

        while (true) {
            if (self::isUser($current) || self::isUserId($current)) {
                return true;
            }

            if ($current instanceof FuncCall && $current->name instanceof Name && strtolower($current->name->toString()) === 'tenant') {
                return true;
            }

            if ($current instanceof PropertyFetch || $current instanceof NullsafePropertyFetch
                || $current instanceof MethodCall || $current instanceof NullsafeMethodCall) {
                $current = $current->var;

                continue;
            }

            return false;
        }
    }

    /**
     * Whether a method chain is rooted at the authenticated user, following only the call spine.
     *
     * Arguments are ignored, so `Invoice::where('x', $request->user()->x)` is not user rooted.
     */
    public static function chainIsUserRooted(Node $node): bool
    {
        $current = $node;

        while ($current instanceof MethodCall || $current instanceof NullsafeMethodCall
            || $current instanceof PropertyFetch || $current instanceof NullsafePropertyFetch) {
            if (self::isUser($current)) {
                return true;
            }

            $current = $current->var;
        }

        return self::isUser($current);
    }

    /**
     * Whether a value is the signed-in user, a value derived from it, or a variable known to hold one.
     *
     * @param  list<string>  $userVariables  Variables assigned from the signed-in user in the action.
     */
    public static function isUserValue(Node $node, array $userVariables): bool
    {
        if (self::isUserDerived($node)) {
            return true;
        }

        $current = $node;

        while ($current instanceof PropertyFetch || $current instanceof NullsafePropertyFetch
            || $current instanceof MethodCall || $current instanceof NullsafeMethodCall) {
            $current = $current->var;
        }

        return $current instanceof Variable && is_string($current->name) && in_array($current->name, $userVariables, true);
    }

    /**
     * Whether the expression only proves that someone is signed in.
     *
     * Matches `auth()->check()`, `Auth::check()`, `! Auth::guest()`, `$this->user() !== null`,
     * `(bool) $this->user()`, `$this->user() instanceof User`, `isset(...)`, and `&&`/`||` of those.
     */
    public static function isAuthenticationOnly(Node $node): bool
    {
        if ($node instanceof Expr\BooleanNot) {
            return self::isAuthenticationOnly($node->expr);
        }

        if ($node instanceof BinaryOp\BooleanAnd || $node instanceof BinaryOp\BooleanOr
            || $node instanceof BinaryOp\LogicalAnd || $node instanceof BinaryOp\LogicalOr) {
            return self::isAuthenticationOnly($node->left) && self::isAuthenticationOnly($node->right);
        }

        if ($node instanceof BinaryOp\Identical || $node instanceof BinaryOp\NotIdentical
            || $node instanceof BinaryOp\Equal || $node instanceof BinaryOp\NotEqual) {
            return (self::isNull($node->left) && self::isUserOrId($node->right))
                || (self::isNull($node->right) && self::isUserOrId($node->left))
                || (self::isBool($node->left) && self::isAuthenticationOnly($node->right))
                || (self::isBool($node->right) && self::isAuthenticationOnly($node->left));
        }

        if ($node instanceof Expr\Cast\Bool_ || $node instanceof Expr\Empty_) {
            return self::isUserOrId($node->expr);
        }

        if ($node instanceof Expr\Instanceof_) {
            return self::isUser($node->expr);
        }

        if ($node instanceof Expr\Isset_) {
            foreach ($node->vars as $var) {
                if (! self::isUserOrId($var)) {
                    return false;
                }
            }

            return $node->vars !== [];
        }

        if ($node instanceof FuncCall && $node->name instanceof Name && strtolower($node->name->toString()) === 'is_null') {
            $arg = $node->args[0] ?? null;

            return $arg instanceof Node\Arg && self::isUserOrId($arg->value);
        }

        if ($node instanceof StaticCall && self::isAuthFacade($node->class) && self::named($node->name, ['check', 'guest'])) {
            return true;
        }

        if (($node instanceof MethodCall || $node instanceof NullsafeMethodCall)
            && self::named($node->name, ['check', 'guest']) && self::isGuardSource($node->var)) {
            return true;
        }

        return self::isUserOrId($node);
    }

    /**
     * Whether a static call or method call reads the authenticated user's id.
     */
    private static function isUserId(Node $node): bool
    {
        if ($node instanceof StaticCall) {
            return self::isAuthFacade($node->class) && self::named($node->name, ['id']);
        }

        if ($node instanceof MethodCall || $node instanceof NullsafeMethodCall) {
            if (self::named($node->name, ['id']) && self::isGuardSource($node->var)) {
                return true;
            }

            return self::named($node->name, ['getkey', 'getauthidentifier']) && self::isUser($node->var);
        }

        return false;
    }

    /**
     * Whether a node is the user, `Auth::id()`, or the user's `id` property.
     */
    private static function isUserOrId(Node $node): bool
    {
        if (self::isUser($node) || self::isUserId($node)) {
            return true;
        }

        return ($node instanceof PropertyFetch || $node instanceof NullsafePropertyFetch)
            && self::named($node->name, ['id'])
            && self::isUser($node->var);
    }

    /**
     * Whether `->user()` called on this node returns the authenticated user.
     */
    private static function isUserSource(Node $node): bool
    {
        // `$request->user()`, `$this->user()`, or any other request variable name.
        if ($node instanceof Variable) {
            return is_string($node->name);
        }

        if ($node instanceof FuncCall) {
            return $node->name instanceof Name && in_array(strtolower($node->name->toString()), ['auth', 'request'], true);
        }

        return self::isGuardSource($node);
    }

    /**
     * Whether a node is an auth guard: `auth()`, `auth('api')`, `Auth::guard()`, or `->guard()`.
     */
    private static function isGuardSource(Node $node): bool
    {
        if ($node instanceof FuncCall) {
            return $node->name instanceof Name && strtolower($node->name->toString()) === 'auth';
        }

        if ($node instanceof StaticCall) {
            return self::isAuthFacade($node->class) && self::named($node->name, ['guard']);
        }

        if ($node instanceof MethodCall || $node instanceof NullsafeMethodCall) {
            return self::named($node->name, ['guard']);
        }

        return false;
    }

    /**
     * Whether a class reference is the Auth facade.
     */
    private static function isAuthFacade(Node $class): bool
    {
        if (! $class instanceof Name) {
            return false;
        }

        return class_basename(ltrim($class->toString(), '\\')) === 'Auth';
    }

    /**
     * Whether an identifier matches one of the lowercase names.
     *
     * @param  list<string>  $names
     */
    private static function named(Node $name, array $names): bool
    {
        return $name instanceof Identifier && in_array(strtolower($name->toString()), $names, true);
    }

    /**
     * Whether a node is the null constant.
     */
    private static function isNull(Node $node): bool
    {
        return $node instanceof Expr\ConstFetch && strtolower($node->name->toString()) === 'null';
    }

    /**
     * Whether a node is the true or false constant.
     */
    private static function isBool(Node $node): bool
    {
        return $node instanceof Expr\ConstFetch && in_array(strtolower($node->name->toString()), ['true', 'false'], true);
    }
}
