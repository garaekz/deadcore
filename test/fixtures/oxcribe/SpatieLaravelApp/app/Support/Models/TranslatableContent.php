<?php

declare(strict_types=1);

namespace App\Support\Models;

use Illuminate\Database\Eloquent\Model;
use Spatie\Translatable\HasTranslations;

abstract class TranslatableContent extends Model
{
    use HasTranslations;

    protected const BASE_TRANSLATABLE = ['title', 'subtitle'];

    protected array $translatable = self::BASE_TRANSLATABLE;
}
