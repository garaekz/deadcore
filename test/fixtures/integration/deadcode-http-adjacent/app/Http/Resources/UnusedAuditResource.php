<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

final class UnusedAuditResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'actor' => $this['actor'],
            'result' => $this['result'],
        ];
    }
}
