<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Filters\PublishedAfterFilter;
use App\Models\Post;
use App\Support\QueryBuilder\AdvancedSearchQuery;
use Spatie\QueryBuilder\AllowedFilter;
use Spatie\QueryBuilder\QueryBuilder;

final class AdvancedSearchController
{
    private const SECONDARY_SORTS = [
        AdvancedSearchQuery::SORT_TITLE,
        AdvancedSearchQuery::SORT_STATUS,
        AdvancedSearchQuery::SORT_UPDATED_AT,
    ];

    private const FIELD_SET = [
        AdvancedSearchQuery::FIELD_POSTS_ID,
        AdvancedSearchQuery::FIELD_POSTS_TITLE,
        AdvancedSearchQuery::FIELD_POSTS_SUMMARY,
        AdvancedSearchQuery::FIELD_POSTS_STATUS,
        AdvancedSearchQuery::FIELD_AUTHORS_NAME,
        AdvancedSearchQuery::FIELD_AUTHORS_EMAIL,
        AdvancedSearchQuery::FIELD_MEDIA_NAME,
    ];

    public function index(): void
    {
        QueryBuilder::for(Post::class)
            ->allowedFilters(self::filters())
            ->allowedIncludes(self::includes())
            ->allowedSorts(self::sorts())
            ->allowedFields(self::fields());
    }

    private static function filters(): array
    {
        return array_merge(
            [
                AllowedFilter::exact(AdvancedSearchQuery::FILTER_STATE, 'posts.status'),
            ],
            self::dynamicFilters(),
            [
                AllowedFilter::custom(AdvancedSearchQuery::FILTER_PUBLISHED_AFTER, new PublishedAfterFilter()),
                AllowedFilter::trashed(),
            ],
        );
    }

    private static function dynamicFilters(): array
    {
        return [
            AllowedFilter::scope(AdvancedSearchQuery::FILTER_OWNED_BY),
            AllowedFilter::callback(AdvancedSearchQuery::FILTER_TAGGED, static function ($query): void {
                $query->where('status', 'published')
                    ->where('visibility', 'public');
            }),
        ];
    }

    private static function includes(): array
    {
        return [
            AdvancedSearchQuery::INCLUDE_AUTHOR_PROFILE,
            AdvancedSearchQuery::INCLUDE_COMMENTS_USER,
            AdvancedSearchQuery::INCLUDE_TAGS_MEDIA,
        ];
    }

    private static function sorts(): array
    {
        return array_merge(
            [AdvancedSearchQuery::SORT_PUBLISHED_AT],
            self::SECONDARY_SORTS,
        );
    }

    private static function fields(): array
    {
        return self::FIELD_SET;
    }
}
