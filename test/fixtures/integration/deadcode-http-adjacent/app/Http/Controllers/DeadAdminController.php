<?php

namespace App\Http\Controllers;

use App\Http\Requests\UnusedAuditRequest;
use App\Http\Resources\UnusedAuditResource;

final class DeadAdminController
{
    public function audit(UnusedAuditRequest $request): UnusedAuditResource
    {
        return new UnusedAuditResource([
            'actor' => $request->input('actor'),
            'result' => 'ignored',
        ]);
    }

    public function export(UnusedAuditRequest $request): UnusedAuditResource
    {
        return new UnusedAuditResource([
            'actor' => $request->input('actor'),
            'result' => 'exported',
        ]);
    }
}
