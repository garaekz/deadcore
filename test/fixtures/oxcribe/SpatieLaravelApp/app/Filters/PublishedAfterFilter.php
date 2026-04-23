<?php

declare(strict_types=1);

namespace App\Filters;

use Illuminate\Database\Eloquent\Builder;

final class PublishedAfterFilter
{
    public function __invoke(Builder $query, mixed $value, string $property): Builder
    {
        return $query->where($property, '>=', $value);
    }
}
