<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Data\PageData;
use App\Http\Resources\PageResource;
use App\Models\Page;

final class PageController
{
    public function update(Page $page, PageData $payload): PageResource
    {
        return new PageResource($page);
    }
}
