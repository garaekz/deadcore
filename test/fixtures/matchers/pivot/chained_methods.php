<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class Team extends Model
{
    /**
     * Multiple chaining patterns for pivot methods.
     */
    public function members(): BelongsToMany
    {
        return $this->belongsToMany(User::class)
            ->withPivot('role')
            ->withPivot('department')
            ->withTimestamps()
            ->as('membership');
    }

    /**
     * Long chain with multiple pivot configurations.
     */
    public function departments(): BelongsToMany
    {
        return $this->belongsToMany(Department::class, 'team_department')
            ->withPivot('budget_allocation')
            ->withPivot('start_date', 'end_date')
            ->withTimestamps()
            ->as('team_dept')
            ->withPivot('manager_id');
    }

    /**
     * Pivot methods called on intermediate variables.
     */
    public function clients(): BelongsToMany
    {
        $baseRelation = $this->belongsToMany(Client::class);
        
        $pivotRelation = $baseRelation->withPivot('contract_type', 'hourly_rate');
        
        return $pivotRelation
            ->withTimestamps()
            ->as('client_contract');
    }

    /**
     * Mixed pivot method patterns.
     */
    public function suppliers(): BelongsToMany
    {
        $relation = $this->belongsToMany(Supplier::class);
        
        $relation->withPivot('contract_value');
        $relation->withTimestamps();
        $relation->as('supplier_contract');
        
        return $relation;
    }
}