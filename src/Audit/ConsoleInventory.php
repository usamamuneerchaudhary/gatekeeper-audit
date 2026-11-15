<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Audit;

use Closure;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Console\ClosureCommand;
use Illuminate\Support\Facades\Artisan;
use ReflectionClass;
use ReflectionFunction;
use ReflectionProperty;
use Symfony\Component\Console\Command\Command;
use Throwable;

final class ConsoleInventory
{
    /**
     * List application console commands.
     *
     * Returns an empty list when the console kernel is missing or the command list cannot be read.
     * Vendor commands and commands outside the application base path are left out.
     *
     * @return list<array{name: string, file: string}>
     */
    public function applicationCommands(): array
    {
        if (! function_exists('app') || ! app()->bound(Kernel::class)) {
            return [];
        }

        try {
            $registered = Artisan::all();
        } catch (Throwable) {
            return [];
        }

        $commands = [];
        $seen = [];

        foreach ($registered as $command) {
            if (! $command instanceof Command) {
                continue;
            }

            $name = $command->getName();

            if (! is_string($name) || $name === '' || isset($seen[$name])) {
                continue;
            }

            $file = $this->fileFor($command);

            if ($file === null || ! $this->isApplicationFile($file)) {
                continue;
            }

            $seen[$name] = true;
            $commands[] = ['name' => $name, 'file' => $file];
        }

        usort($commands, static fn (array $left, array $right): int => strcmp($left['name'], $right['name']));

        return $commands;
    }

    /**
     * Source file for a command. Closure commands use the file that defined the callback.
     *
     * Returns null when the file cannot be resolved.
     */
    private function fileFor(Command $command): ?string
    {
        if ($command instanceof ClosureCommand) {
            try {
                $callback = (new ReflectionProperty($command, 'callback'))->getValue($command);

                if ($callback instanceof Closure) {
                    $file = (new ReflectionFunction($callback))->getFileName();

                    if (is_string($file) && $file !== '') {
                        return $file;
                    }
                }
            } catch (Throwable) {
                return null;
            }

            return null;
        }

        try {
            $file = (new ReflectionClass($command))->getFileName();
        } catch (Throwable) {
            return null;
        }

        return is_string($file) && $file !== '' ? $file : null;
    }

    /**
     * Whether a file lives in the application and outside vendor.
     *
     * Returns false when the path cannot be resolved.
     */
    private function isApplicationFile(string $file): bool
    {
        $real = realpath($file);
        $base = realpath(base_path());

        if ($real === false || $base === false) {
            return false;
        }

        $real = str_replace('\\', '/', $real);
        $base = rtrim(str_replace('\\', '/', $base), '/');

        if (! str_starts_with($real, $base.'/')) {
            return false;
        }

        return ! str_starts_with($real, $base.'/vendor/');
    }
}
