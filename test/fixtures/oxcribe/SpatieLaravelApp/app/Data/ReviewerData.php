<?php

declare(strict_types=1);

namespace App\Data;

use Spatie\LaravelData\Data;

final class ReviewerData extends Data
{
    public function __construct(
        public string $name,
        public ?SeoData $approval = null,
    ) {
    }
}
