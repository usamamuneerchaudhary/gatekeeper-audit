<?php

declare(strict_types=1);

namespace Usamamuneerchaudhary\GatekeeperAudit\Console;

use Illuminate\Console\Command;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\Auditor;
use Usamamuneerchaudhary\GatekeeperAudit\Audit\Baseline;

class BaselineCommand extends Command
{
    protected $signature = 'gatekeeper:baseline
        {--path= : Baseline file to write}
        {--only= : Only audit URIs starting with this prefix}
        {--include-vendor : Also audit vendor routes}
        {--include-public : Also audit routes without auth middleware}';

    protected $description = 'Write the current Gatekeeper findings to a baseline file.';

    /**
     * Audit without a baseline and write every finding id to the file.
     *
     * Returns 2 when the audit itself cannot run.
     */
    public function handle(Auditor $auditor): int
    {
        try {
            $result = $auditor->audit(
                includeVendor: (bool) $this->option('include-vendor'),
                includePublic: (bool) $this->option('include-public'),
                only: $this->option('only') !== null ? (string) $this->option('only') : null,
            );

            $path = $this->baselinePath();
            Baseline::write($path, $result->findings);
        } catch (\Throwable $exception) {
            $this->error('Gatekeeper baseline could not run: '.$exception->getMessage());

            return 2;
        }

        $this->info(sprintf('Wrote %d finding(s) to %s.', count($result->findings), $path));

        return self::SUCCESS;
    }

    /**
     * Resolve the baseline path from the option or published config.
     */
    private function baselinePath(): string
    {
        $option = $this->option('path');
        $path = is_string($option) && $option !== '' ? $option : (string) config('gatekeeper.baseline', 'gatekeeper-baseline.json');

        if (str_starts_with($path, '/')) {
            return $path;
        }

        return base_path($path);
    }
}
