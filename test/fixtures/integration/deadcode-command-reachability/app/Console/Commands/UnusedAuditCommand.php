<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

final class UnusedAuditCommand extends Command
{
    protected $signature = 'audit:unused';

    protected $description = 'Unused command fixture for deadcode reachability.';

    public function handle(): int
    {
        $this->line('unused');

        return self::SUCCESS;
    }
}
