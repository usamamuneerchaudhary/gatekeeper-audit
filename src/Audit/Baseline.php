<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

final class Baseline
{
    /**
     * Read finding ids from a baseline file. A missing file yields an empty set.
     *
     * @return list<string>
     */
    public static function read(string $path): array
    {
        if (! is_file($path)) {
            return [];
        }

        $contents = file_get_contents($path);

        if ($contents === false) {
            throw new \RuntimeException("Baseline file is not readable: {$path}");
        }

        $decoded = json_decode($contents, true);

        if (! is_array($decoded)) {
            throw new \RuntimeException("Baseline file is not valid JSON: {$path}");
        }

        $ids = $decoded['ids'] ?? $decoded['findings'] ?? [];

        if (! is_array($ids)) {
            throw new \RuntimeException("Baseline file has no finding list: {$path}");
        }

        $result = [];

        foreach ($ids as $entry) {
            if (is_string($entry)) {
                $result[] = $entry;
            } elseif (is_array($entry) && is_string($entry['id'] ?? null)) {
                $result[] = $entry['id'];
            }
        }

        return array_values(array_unique($result));
    }

    /**
     * Write a baseline file for the given findings.
     *
     * @param  list<Finding>  $findings
     */
    public static function write(string $path, array $findings): void
    {
        $entries = [];

        foreach ($findings as $finding) {
            $entries[] = [
                'id' => $finding->id(),
                'rule' => $finding->rule,
                'severity' => $finding->severity->value,
                'route' => implode('|', $finding->methods).' '.$finding->uri,
                'action' => $finding->action,
            ];
        }

        usort($entries, static fn (array $left, array $right): int => strcmp($left['id'], $right['id']));

        $payload = json_encode([
            'version' => 'gatekeeper.baseline.v1',
            'findings' => $entries,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if ($payload === false) {
            throw new \RuntimeException('Baseline could not be encoded as JSON.');
        }

        $directory = dirname($path);

        if (! is_dir($directory)) {
            mkdir($directory, 0775, true);
        }

        file_put_contents($path, $payload.PHP_EOL);
    }
}
