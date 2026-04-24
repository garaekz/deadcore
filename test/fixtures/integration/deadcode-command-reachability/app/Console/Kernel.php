<?php

namespace App\Console;

use App\Console\Commands\ReachableMaintenanceCommand;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;

final class Kernel extends ConsoleKernel
{
    protected $commands = [
        ReachableMaintenanceCommand::class,
    ];
}
