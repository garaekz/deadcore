<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

final class ReachableMaintenanceCommand extends Command
{
    protected $signature = 'maintenance:reachable';

    protected $description = 'Run the reachable maintenance workflow.';

    public function handle(): int
    {
        $this->info('reachable');

        return self::SUCCESS;
    }
}
