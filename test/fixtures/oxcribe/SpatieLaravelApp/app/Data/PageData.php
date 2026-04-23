<?php

declare(strict_types=1);

namespace App\Data;

use Spatie\LaravelData\Data;

final class PageData extends Data
{
    public function __construct(
        public string $title,
        public ?SeoData $seo = null,
    ) {
    }
}
