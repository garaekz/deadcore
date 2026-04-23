<?php

declare(strict_types=1);

namespace App\Data;

use Spatie\LaravelData\Data;

final class PublishPostData extends Data
{
    public function __construct(
        public SeoData $seo,
        public ?ReviewerData $reviewer = null,
        public ?string $notes = null,
    ) {
    }
}
