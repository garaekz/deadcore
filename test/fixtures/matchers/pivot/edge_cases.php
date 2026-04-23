<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class EdgeCaseModel extends Model
{
    /**
     * Empty pivot fields - should not match.
     */
    public function emptyPivot(): BelongsToMany
    {
        return $this->belongsToMany(OtherModel::class)
            ->withPivot()
            ->withTimestamps();
    }

    /**
     * Single pivot field.
     */
    public function singleField(): BelongsToMany
    {
        return $this->belongsToMany(SimpleModel::class)
            ->withPivot('status');
    }

    /**
     * No pivot configuration at all.
     */
    public function noPivot(): BelongsToMany
    {
        return $this->belongsToMany(BasicModel::class);
    }

    /**
     * Only timestamps, no pivot fields.
     */
    public function onlyTimestamps(): BelongsToMany
    {
        return $this->belongsToMany(TimestampModel::class)
            ->withTimestamps();
    }

    /**
     * Only alias, no other pivot methods.
     */
    public function onlyAlias(): BelongsToMany
    {
        return $this->belongsToMany(AliasModel::class)
            ->as('custom_name');
    }

    /**
     * Pivot with array notation (alternative syntax).
     */
    public function arrayPivot(): BelongsToMany
    {
        return $this->belongsToMany(ArrayModel::class)
            ->withPivot(['field1', 'field2', 'field3'])
            ->withTimestamps();
    }

    /**
     * Mixed quotes in pivot fields.
     */
    public function mixedQuotes(): BelongsToMany
    {
        return $this->belongsToMany(QuoteModel::class)
            ->withPivot("double_quote_field", 'single_quote_field')
            ->as("alias_with_double_quotes");
    }

    /**
     * Non-pivot as() method should not match incorrectly.
     */
    public function nonPivotAs(): BelongsToMany
    {
        $result = $this->belongsToMany(NonPivotModel::class);
        $transformed = $result->get()->map(function ($item) {
            return $item->as('something');
        });
        return $result;
    }
}