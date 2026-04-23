<?php

declare(strict_types=1);

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

final class PostResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'title' => $this->title,
            'summary' => $this->summary,
            'published_at' => $this->published_at,
            'is_featured' => $this->is_featured,
            'seo' => new SeoResource($this->whenLoaded('seo')),
            'tags' => TagResource::collection($this->whenLoaded('tags')),
        ];
    }
}
