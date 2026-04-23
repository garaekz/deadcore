<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Data\SeriesData;
use App\Http\Resources\SeriesResource;
use App\Models\Series;

final class SeriesController
{
    public function update(Series $series, SeriesData $payload): SeriesResource
    {
        return new SeriesResource($series);
    }
}
