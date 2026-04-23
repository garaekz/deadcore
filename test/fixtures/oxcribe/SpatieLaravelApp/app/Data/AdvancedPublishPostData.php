<?php

declare(strict_types=1);

namespace App\Data;

require_once __DIR__.'/StorePostData.php';

use Spatie\LaravelData\Attributes\DataCollectionOf;
use Spatie\LaravelData\Lazy;
use Spatie\LaravelData\Optional;

final class AdvancedPublishPostData extends StorePostData
{
    #[DataCollectionOf(ReviewerData::class)]
    public array $reviewers;

    #[DataCollectionOf(ReviewerData::class)]
    public array $approvalHistory;

    public Optional|SeoData $preview;

    public Lazy|SeoData $teaser;

    public ?ReviewerData $reviewer;

    public function __construct(
        string $title,
        string $summary,
        SeoData $seo,
        public bool $featured,
        array $reviewers,
        #[DataCollectionOf(ReviewerData::class)]
        array $approvalHistory,
        Optional|SeoData $preview,
        Lazy|SeoData $teaser,
        ?ReviewerData $reviewer = null,
    ) {
        parent::__construct($title, $summary, $seo);
        $this->reviewers = $reviewers;
        $this->approvalHistory = $approvalHistory;
        $this->preview = $preview;
        $this->teaser = $teaser;
        $this->reviewer = $reviewer;
    }
}
