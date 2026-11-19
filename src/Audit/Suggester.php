<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

use Usamamuneerchaudhary\GatekeeperAudit\Enums\SuggestionMode;

final class Suggester
{
    /**
     * Read ownership columns used when a scoping hint names a column.
     *
     * @param  array<string, mixed>  $config
     */
    public function __construct(private readonly array $config) {}

    /**
     * Build the fix an agent should attempt for one finding.
     *
     * A patch is the usual framework call and can be applied as written.
     * A hint is a shape that still needs the real owner column, ability, or relation.
     */
    public function make(string $rule, RouteSubject $subject, ActionAnalysis $analysis): Suggestion
    {
        return match ($rule) {
            'object_authorization' => $this->objectAuthorization($subject),
            'trivial_form_request' => $this->formRequest($subject, $analysis),
            'trivial_policy' => $this->policy($analysis),
            'missing_authorization' => $this->missingAuthorization($subject),
            'unscoped_lookup', 'unscoped_collection' => $this->lookup($subject, $analysis, $rule),
            default => new Suggestion(
                SuggestionMode::Hint,
                'The action source could not be parsed, so no patch is offered.',
                ['Open the action and confirm an object-level check by hand.'],
            ),
        };
    }

    /**
     * Suggest an authorize call for a route that accepts an object.
     */
    private function objectAuthorization(RouteSubject $subject): Suggestion
    {
        $ability = $this->ability($subject);
        $variable = $this->variable($subject);
        $call = $subject->isClosure
            ? "Gate::authorize('{$ability}', \${$variable});"
            : "\$this->authorize('{$ability}', \${$variable});";

        $steps = [
            "Authorize `{$ability}` on `\${$variable}` before the action uses it.",
            'Keep the routed model in the check. A role or class-level can middleware does not clear this finding.',
        ];

        if ($subject->isClosure && $this->closureIsArrow($subject->file, $subject->line)) {
            $steps[] = 'This closure is an arrow function, so it has no body to insert into. Rewrite it as a block, then add the Gate call.';

            return new Suggestion(
                SuggestionMode::Hint,
                "Authorize the routed {$variable} before this arrow function returns.",
                $steps,
                $this->addedLine($call),
            );
        }

        $diff = $this->insertAfterOpeningBrace($subject->file, $subject->line, $call);

        if ($diff === null) {
            $steps[] = 'Add the authorize call as the first line of the action. The source shape was not safe to rewrite automatically.';

            return new Suggestion(
                SuggestionMode::Hint,
                "Authorize the routed {$variable} before this action uses it.",
                $steps,
                $this->addedLine($call),
            );
        }

        return new Suggestion(
            SuggestionMode::Patch,
            "Authorize the routed {$variable} before this action uses it.",
            $steps,
            $diff,
        );
    }

    /**
     * Suggest a FormRequest authorize() body that checks the routed model.
     */
    private function formRequest(RouteSubject $subject, ActionAnalysis $analysis): Suggestion
    {
        $ability = $this->ability($subject);
        $variable = $this->variable($subject);
        $replacement = "return \$this->user()?->can('{$ability}', \$this->route('{$variable}')) ?? false;";
        $class = $analysis->formRequestClass;
        $file = $this->fileContaining($class, 'function authorize');
        $diff = $this->replaceAuthorizeReturn($file, $replacement);

        $steps = [
            "Make authorize() check `{$ability}` against the `{$variable}` route parameter.",
            'Returning true, or only checking that a user is signed in, does not clear this finding.',
        ];

        if ($class !== null && $file !== null && $this->fileForClass($class) !== $file) {
            $steps[] = 'authorize() is inherited. Change the parent, or override it on this request.';
        }

        if ($diff === null) {
            $steps[] = 'Add an authorize() method when this request does not define one.';

            return new Suggestion(
                SuggestionMode::Hint,
                'The FormRequest does not check the routed model.',
                $steps,
                $this->addedLine($replacement),
            );
        }

        return new Suggestion(
            SuggestionMode::Patch,
            'Check the routed model inside authorize().',
            $steps,
            $diff,
        );
    }

    /**
     * A policy that always returns true needs a real ownership rule, which this tool cannot know.
     */
    private function policy(ActionAnalysis $analysis): Suggestion
    {
        $method = null;

        if (is_string($analysis->policyEvidence) && preg_match('/::([A-Za-z0-9_]+)\(\) returns true$/', $analysis->policyEvidence, $matches) === 1) {
            $method = $matches[1];
        }

        $target = $method === null ? 'the policy method' : "{$method}()";

        return new Suggestion(
            SuggestionMode::Hint,
            "{$target} always allows the action.",
            [
                "Open {$target} and replace `return true` with the ownership rule for this model.",
                'Use both the signed-in user and the model. A role check does not belong in this method.',
                'Gatekeeper does not know the owner column, so this finding has no diff to apply.',
            ],
        );
    }

    /**
     * Suggest a real authorization check for a write that has none.
     */
    private function missingAuthorization(RouteSubject $subject): Suggestion
    {
        $ability = $this->ability($subject);

        return new Suggestion(
            SuggestionMode::Hint,
            "Add a real `{$ability}` check before this action writes.",
            [
                "Call authorize('{$ability}', ...) or move the same check into a FormRequest.",
                'Do not return true from authorize(), and do not stop at a role middleware check.',
            ],
        );
    }

    /**
     * Suggest scoping a raw lookup. The column is an example, so this stays a hint.
     */
    private function lookup(RouteSubject $subject, ActionAnalysis $analysis, string $rule): Suggestion
    {
        $column = $this->ownershipColumn();
        $lookup = null;

        foreach ($analysis->lookups as $candidate) {
            if ($candidate['rule'] === $rule) {
                $lookup = $candidate;
                break;
            }
        }

        $expression = is_array($lookup) ? $lookup['expression'] : 'the query';
        $file = $subject->file;
        $line = is_array($lookup) ? $lookup['line'] : null;
        $diff = null;

        if ($file !== null && $line !== null) {
            $original = $this->lineAt($file, $line);

            if ($original !== null) {
                $rewritten = $this->scopeRewrite($original, $column);
                $diff = $rewritten === null ? null : $this->replacedLine($original, $rewritten);
            }
        }

        $steps = [
            "The flagged query is `{$expression}`.",
            "Scope it through the signed-in user before it runs. `{$column}` is the first configured ownership column, so change it when this model uses another.",
            'A global scope or a scoped binding on the injected parameter does not cover a second raw query.',
        ];

        return new Suggestion(
            SuggestionMode::Hint,
            'Scope this query through the signed-in user.',
            $steps,
            $diff,
        );
    }

    /**
     * Conventional ability from the action name, then from the HTTP verb.
     */
    private function ability(RouteSubject $subject): string
    {
        $fromName = match (strtolower((string) $subject->method)) {
            'index' => 'viewAny',
            'create', 'store' => 'create',
            'show' => 'view',
            'edit', 'update' => 'update',
            'destroy' => 'delete',
            'restore' => 'restore',
            'forcedelete' => 'forceDelete',
            default => null,
        };

        if ($fromName !== null) {
            return $fromName;
        }

        if (in_array('DELETE', $subject->methods, true)) {
            return 'delete';
        }

        if (array_intersect($subject->methods, ['PUT', 'PATCH']) !== []) {
            return 'update';
        }

        if (in_array('POST', $subject->methods, true)) {
            return 'create';
        }

        return 'view';
    }

    /**
     * Route parameter a suggestion should name.
     */
    private function variable(RouteSubject $subject): string
    {
        return $subject->objectParameterNames()[0] ?? 'model';
    }

    /**
     * First configured ownership column, used only as a labeled example.
     */
    private function ownershipColumn(): string
    {
        $ownership = is_array($this->config['ownership'] ?? null) ? $this->config['ownership'] : [];
        $columns = is_array($ownership['columns'] ?? null) ? $ownership['columns'] : [];
        $column = $columns[0] ?? 'user_id';

        return is_string($column) && $column !== '' ? $column : 'user_id';
    }

    /**
     * Insert a statement inside the action body.
     *
     * Returns null when the file has no brace to anchor the statement.
     */
    private function insertAfterOpeningBrace(?string $file, ?int $line, string $statement): ?string
    {
        $lines = $this->lines($file);

        if ($lines === null || $line === null) {
            return null;
        }

        $start = max(0, $line - 1);
        $last = min(count($lines) - 1, $start + 15);
        $brace = null;

        for ($index = $start; $index <= $last; $index++) {
            if (str_contains($lines[$index], '{')) {
                $brace = $index;
                break;
            }
        }

        if ($brace === null) {
            return null;
        }

        $braceText = rtrim($lines[$brace], "\r\n");
        $open = strrpos($braceText, '{');
        $close = strrpos($braceText, '}');

        if ($open !== false && $close !== false && $close > $open) {
            return $this->expandOneLineBody($file, $braceText, $open, $close, $statement);
        }

        $from = max(0, $brace - 1);
        $to = min(count($lines) - 1, $brace + 3);
        $diff = $this->pathHeader($file);

        for ($index = $from; $index <= $to; $index++) {
            $text = rtrim($lines[$index], "\r\n");
            $diff[] = ' '.$text;

            if ($index === $brace) {
                $indent = str_repeat(' ', (strlen($text) - strlen(ltrim($text))) + 4);
                $diff[] = '+'.$indent.$statement;
            }
        }

        return implode("\n", $diff);
    }

    /**
     * Replace `return true` inside authorize(), stopping at the next method.
     */
    private function replaceAuthorizeReturn(?string $file, string $replacement): ?string
    {
        $lines = $this->lines($file);

        if ($lines === null) {
            return null;
        }

        $inside = false;

        foreach ($lines as $line) {
            if (! $inside && preg_match('/function\s+authorize\s*\(/', $line) === 1) {
                $inside = true;
            }

            if (! $inside) {
                continue;
            }

            if (preg_match('/function\s+(?!authorize\b)\w+\s*\(/', $line) === 1) {
                break;
            }

            if (! str_contains($line, 'return true;')) {
                continue;
            }

            $text = rtrim($line, "\r\n");
            $indent = str_repeat(' ', strlen($text) - strlen(ltrim($text)));

            return implode("\n", [
                ...$this->pathHeader($file),
                '-'.$text,
                '+'.$indent.$replacement,
            ]);
        }

        return null;
    }

    /**
     * Rewrite a one-line lookup so the example where clause is visible.
     */
    private function scopeRewrite(string $line, string $column): ?string
    {
        $text = rtrim($line, "\r\n");
        $where = "where('{$column}', \$request->user()->id)->";

        $prefix = '(\s*)((?:return\s+|\$\w+\s*=\s*))';

        if (preg_match('/^'.$prefix.'(.+)::(findOrFail|find|firstOrFail)\((.*)\);\s*$/', $text, $matches) === 1) {
            return $matches[1].$matches[2].$matches[3].'::query()->'.$where.$matches[4].'('.$matches[5].');';
        }

        if (preg_match('/^'.$prefix.'(.+)->(get|paginate|simplePaginate|cursorPaginate|find|findOrFail|first|firstOrFail)\((.*)\);\s*$/', $text, $matches) === 1) {
            return $matches[1].$matches[2].$matches[3].'->'.$where.$matches[4].'('.$matches[5].');';
        }

        return null;
    }

    /**
     * Whether the closure on this line is an arrow function.
     */
    private function closureIsArrow(?string $file, ?int $line): bool
    {
        if ($line === null) {
            return false;
        }

        $text = $this->lineAt((string) $file, $line);

        return is_string($text)
            && preg_match('/\bfn\b/', $text) === 1
            && str_contains($text, '=>');
    }

    /**
     * Move a same-line body onto its own lines and place the statement inside it.
     */
    private function expandOneLineBody(?string $file, string $text, int $open, int $close, string $statement): string
    {
        $indent = str_repeat(' ', strlen($text) - strlen(ltrim($text)));
        $inner = $indent.'    ';
        $head = rtrim(substr($text, 0, $open + 1));
        $body = trim(substr($text, $open + 1, $close - $open - 1));
        $tail = $indent.substr($text, $close);
        $added = [$head, $inner.$statement];

        if ($body !== '') {
            $added[] = $inner.$body;
        }

        $added[] = $tail;
        $diff = [...$this->pathHeader($file), '-'.$text];

        foreach ($added as $line) {
            $diff[] = '+'.$line;
        }

        return implode("\n", $diff);
    }

    /**
     * One file line, when the line number exists.
     */
    private function lineAt(string $file, int $line): ?string
    {
        $lines = $this->lines($file);

        if ($lines === null || ! isset($lines[$line - 1])) {
            return null;
        }

        return $lines[$line - 1];
    }

    /**
     * File lines for a readable path, or null when the file is missing.
     *
     * @return list<string>|null
     */
    private function lines(?string $file): ?array
    {
        if ($file === null || ! is_file($file)) {
            return null;
        }

        $lines = file($file);

        return $lines === false ? null : $lines;
    }

    /**
     * Source file for a class, walking parents until a line contains the needle.
     */
    private function fileContaining(?string $class, string $needle): ?string
    {
        $current = $class;

        for ($depth = 0; $depth < 5 && is_string($current) && $current !== ''; $depth++) {
            if (str_starts_with($current, 'Illuminate\\') || ! class_exists($current)) {
                break;
            }

            $file = $this->fileForClass($current);

            if ($file !== null) {
                $contents = file_get_contents($file);

                if ($contents !== false && str_contains($contents, $needle)) {
                    return $file;
                }
            }

            $parent = get_parent_class($current);
            $current = is_string($parent) ? $parent : null;
        }

        return null;
    }

    /**
     * Source file for a class that is already loaded.
     */
    private function fileForClass(?string $class): ?string
    {
        if ($class === null || ! class_exists($class)) {
            return null;
        }

        try {
            $file = (new \ReflectionClass($class))->getFileName();
        } catch (\Throwable) {
            return null;
        }

        return is_string($file) && $file !== '' ? $file : null;
    }

    /**
     * A diff context line naming the file the hunk belongs to.
     *
     * @return list<string>
     */
    private function pathHeader(?string $file): array
    {
        return $file === null ? [] : [' '.PhpFileIndex::relativePath($file)];
    }

    /**
     * A diff that only adds a line.
     */
    private function addedLine(string $statement): string
    {
        return '+        '.$statement;
    }

    /**
     * A one-line replacement diff.
     */
    private function replacedLine(string $original, string $rewritten): string
    {
        return '-'.rtrim($original, "\r\n")."\n+".rtrim($rewritten, "\r\n");
    }
}
