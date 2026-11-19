<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit;

use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\ActionInspector;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\Auditor;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\ConsoleInventory;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\ModelInspector;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\PhpFileIndex;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\RouteFileMap;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\RouteScanner;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\Suggester;
use Usamamuneerchaudhary\GatekeeperAudit\Console\AuditCommand;
use Usamamuneerchaudhary\GatekeeperAudit\Console\BaselineCommand;

final class GatekeeperServiceProvider extends ServiceProvider
{
    /**
     * Register the audit pipeline as container singletons.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/gatekeeper.php', 'gatekeeper');

        $this->app->singleton(PhpFileIndex::class, static fn (): PhpFileIndex => new PhpFileIndex);

        $this->app->singleton(ModelInspector::class, function (): ModelInspector {
            return new ModelInspector($this->app->make(PhpFileIndex::class), $this->gatekeeperConfig());
        });

        $this->app->singleton(RouteFileMap::class, static fn (): RouteFileMap => new RouteFileMap);

        $this->app->singleton(RouteScanner::class, function (): RouteScanner {
            return new RouteScanner(
                $this->app->make(Router::class),
                $this->gatekeeperConfig(),
                $this->app->make(RouteFileMap::class),
            );
        });

        $this->app->singleton(ActionInspector::class, function (): ActionInspector {
            return new ActionInspector(
                $this->app->make(PhpFileIndex::class),
                $this->gatekeeperConfig(),
            );
        });

        $this->app->singleton(Auditor::class, function (): Auditor {
            $config = $this->gatekeeperConfig();

            return new Auditor(
                $this->app->make(RouteScanner::class),
                $this->app->make(ActionInspector::class),
                $this->app->make(ModelInspector::class),
                $config,
                new Suggester($config),
                $this->app->make(PhpFileIndex::class),
                new ConsoleInventory,
            );
        });
    }

    /**
     * Publish config and register the Artisan commands.
     */
    public function boot(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__.'/../config/gatekeeper.php' => $this->app->configPath('gatekeeper.php'),
        ], 'gatekeeper-config');

        $this->commands([
            AuditCommand::class,
            BaselineCommand::class,
        ]);
    }

    /**
     * Current package config as a plain array.
     *
     * @return array<string, mixed>
     */
    private function gatekeeperConfig(): array
    {
        $config = $this->app['config']->get('gatekeeper', []);

        return is_array($config) ? $config : [];
    }
}
