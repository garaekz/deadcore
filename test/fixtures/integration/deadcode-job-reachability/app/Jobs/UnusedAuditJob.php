<?php

namespace App\Jobs;

final class UnusedAuditJob
{
    public function __construct(
        public string $reportName = 'audit'
    ) {
    }

    public function handle(): void
    {
    }
}
