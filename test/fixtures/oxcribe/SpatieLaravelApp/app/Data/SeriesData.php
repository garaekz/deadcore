<?php

declare(strict_types=1);

namespace App\Data;

use Spatie\LaravelData\Data;

final class SeriesData extends Data
{
    public function __construct(
        public string $title,
        public string $subtitle,
        public ?SeoData $seo = null,
    ) {
    }
}
