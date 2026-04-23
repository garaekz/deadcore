<?php

declare(strict_types=1);

namespace App\Support\QueryBuilder;

use App\Filters\PublishedAfterFilter;
use Spatie\QueryBuilder\AllowedFilter;

final class AdvancedSearchQuery
{
    public const FILTER_STATE = 'state';
    public const FILTER_OWNED_BY = 'ownedBy';
    public const FILTER_TAGGED = 'tagged';
    public const FILTER_PUBLISHED_AFTER = 'published_after';

    public const INCLUDE_AUTHOR_PROFILE = 'author.profile';
    public const INCLUDE_COMMENTS_USER = 'comments.user';
    public const INCLUDE_TAGS_MEDIA = 'tags.media';

    public const SORT_PUBLISHED_AT = '-published_at';
    public const SORT_TITLE = 'title';
    public const SORT_STATUS = 'status';
    public const SORT_UPDATED_AT = 'updated_at';

    public const FIELD_POSTS_ID = 'posts.id';
    public const FIELD_POSTS_TITLE = 'posts.title';
    public const FIELD_POSTS_SUMMARY = 'posts.summary';
    public const FIELD_POSTS_STATUS = 'posts.status';
    public const FIELD_AUTHORS_NAME = 'authors.name';
    public const FIELD_AUTHORS_EMAIL = 'authors.email';
    public const FIELD_MEDIA_NAME = 'media.name';
}
