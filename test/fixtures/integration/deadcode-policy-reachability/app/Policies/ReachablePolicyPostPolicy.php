<?php

namespace App\Policies;

use App\Models\PolicyPost;

final class ReachablePolicyPostPolicy
{
    public function view(object $user, PolicyPost $policyPost): bool
    {
        return true;
    }
}
