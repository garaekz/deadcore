<?php

declare(strict_types=1);

namespace App\Models;

require_once __DIR__.'/../Support/Models/TranslatableContent.php';

use App\Support\Models\TranslatableContent;

final class Series extends TranslatableContent
{
    private const SERIES_TRANSLATABLE = ['description'];

    protected array $translatable = self::SERIES_TRANSLATABLE;
}
