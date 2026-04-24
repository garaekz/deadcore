<?php

namespace App\Policies;

use App\Models\PolicyPost;

final class UnusedAuditPolicy
{
    public function viewAny(object $user, PolicyPost $policyPost): bool
    {
        return false;
    }
}
