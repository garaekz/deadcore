<?php

namespace App\Http\Controllers;

use App\Models\PolicyPost;

final class PolicyPostController
{
    public function show(PolicyPost $policyPost): array
    {
        return ['id' => $policyPost->getKey()];
    }
}
