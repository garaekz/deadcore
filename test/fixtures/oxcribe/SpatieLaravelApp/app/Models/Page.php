<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Spatie\Translatable\HasTranslations;

final class Page extends Model
{
    use HasTranslations;

    protected array $translatable = ['title'];
}
