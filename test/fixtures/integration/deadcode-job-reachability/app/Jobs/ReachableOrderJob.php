<?php

namespace App\Jobs;

final class ReachableOrderJob
{
    public function __construct(
        public string $orderId
    ) {
    }

    public static function dispatch(string $orderId): self
    {
        return new self($orderId);
    }

    public function handle(): void
    {
    }
}
