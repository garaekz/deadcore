<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Database\Eloquent\Relations\MorphOne;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Database\Eloquent\Builder;

/**
 * Test fixture demonstrating complex polymorphic relationship patterns:
 * - Nested polymorphic relationships (polymorphic chains)
 * - Polymorphic relationships with constraints and scopes
 * - Complex discriminator mappings
 * - Mixed relationship types in single models
 * - Deep relationship traversal patterns
 */

// Model with nested polymorphic relationships
class ActivityLog extends Model
{
    protected $fillable = ['event', 'description', 'properties', 'subject_id', 'subject_type', 'causer_id', 'causer_type'];
    
    protected $casts = [
        'properties' => 'array',
    ];
    
    /**
     * Get the subject that triggered this activity (polymorphic)
     */
    public function subject(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get the user/entity that caused this activity (polymorphic)
     */
    public function causer(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get related activities for the same subject
     */
    public function relatedActivities(): MorphMany
    {
        return $this->morphMany(self::class, 'subject');
    }
    
    /**
     * Constrained polymorphic relationship - only certain models
     */
    public function constrainedSubject(): MorphTo
    {
        return $this->morphTo('subject')
            ->whereIn('subject_type', ['App\Models\Post', 'App\Models\User', 'App\Models\Order']);
    }
}

// Model demonstrating polymorphic relationship chains
class Notification extends Model
{
    protected $fillable = ['type', 'notifiable_id', 'notifiable_type', 'data', 'read_at'];
    
    protected $casts = [
        'data' => 'array',
        'read_at' => 'datetime',
    ];
    
    /**
     * Get the entity being notified (User, Team, etc.)
     */
    public function notifiable(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get the notification's subject (what the notification is about)
     */
    public function subject(): MorphTo
    {
        return $this->morphTo('subject', 'subject_type', 'subject_id');
    }
    
    /**
     * Get activities related to this notification
     */
    public function activities(): MorphMany
    {
        return $this->morphMany(ActivityLog::class, 'subject');
    }
    
    /**
     * Get the notification's attachments
     */
    public function attachments(): MorphMany
    {
        return $this->morphMany(Attachment::class, 'attachable');
    }
}

// Model with complex polymorphic patterns and multiple discriminators
class MediaItem extends Model
{
    protected $fillable = ['type', 'path', 'metadata', 'mediable_id', 'mediable_type', 'collection_name'];
    
    protected $casts = [
        'metadata' => 'array',
    ];
    
    /**
     * Get the model this media belongs to
     */
    public function mediable(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get conversions of this media item
     */
    public function conversions(): MorphMany
    {
        return $this->morphMany(MediaConversion::class, 'convertible');
    }
    
    /**
     * Get the media collection this belongs to
     */
    public function collection(): MorphTo
    {
        return $this->morphTo('collection', 'collection_type', 'collection_id');
    }
    
    /**
     * Scope for specific media collections
     */
    public function scopeInCollection(Builder $query, string $collection): Builder
    {
        return $query->where('collection_name', $collection);
    }
    
    /**
     * Polymorphic relationship with custom constraints
     */
    public function publicMediable(): MorphTo
    {
        return $this->morphTo('mediable')
            ->where('is_public', true)
            ->whereNotNull('published_at');
    }
}

// Model for media conversions (nested polymorphic)
class MediaConversion extends Model
{
    protected $fillable = ['name', 'path', 'size', 'convertible_id', 'convertible_type'];
    
    /**
     * Get the convertible model (MediaItem, Image, etc.)
     */
    public function convertible(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get activities for this conversion
     */
    public function processingActivities(): MorphMany
    {
        return $this->morphMany(ActivityLog::class, 'subject')
            ->where('event', 'like', 'conversion.%');
    }
}

// Model with multiple polymorphic relationships and complex discriminators
class Audit extends Model
{
    protected $fillable = ['event', 'auditable_id', 'auditable_type', 'user_id', 'user_type', 'old_values', 'new_values'];
    
    protected $casts = [
        'old_values' => 'array',
        'new_values' => 'array',
    ];
    
    /**
     * Get the auditable model
     */
    public function auditable(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get the user who made the change (can be User, Admin, System)
     */
    public function user(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get related audits for the same entity
     */
    public function relatedAudits(): MorphMany
    {
        return $this->morphMany(self::class, 'auditable');
    }
    
    /**
     * Polymorphic relationship with specific user types only
     */
    public function humanUser(): MorphTo
    {
        return $this->morphTo('user')
            ->whereIn('user_type', ['App\Models\User', 'App\Models\Admin']);
    }
}

// Model demonstrating polymorphic inheritance patterns
class ContentBlock extends Model
{
    protected $fillable = ['type', 'content', 'settings', 'blockable_id', 'blockable_type', 'order'];
    
    protected $casts = [
        'content' => 'array',
        'settings' => 'array',
    ];
    
    /**
     * Get the parent content (Page, Post, Email, etc.)
     */
    public function blockable(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get nested content blocks
     */
    public function childBlocks(): MorphMany
    {
        return $this->morphMany(self::class, 'blockable');
    }
    
    /**
     * Get the parent block (for nested blocks)
     */
    public function parentBlock(): MorphTo
    {
        return $this->morphTo('blockable')
            ->where('blockable_type', self::class);
    }
    
    /**
     * Get media items for this block
     */
    public function media(): MorphMany
    {
        return $this->morphMany(MediaItem::class, 'mediable');
    }
    
    /**
     * Scope for specific block types
     */
    public function scopeOfType(Builder $query, string $type): Builder
    {
        return $query->where('type', $type);
    }
}

// Model with polymorphic relationships using custom columns and complex discriminators
class Permission extends Model
{
    protected $fillable = ['name', 'guard_name', 'permissionable_id', 'permissionable_type'];
    
    /**
     * Get the model this permission applies to
     */
    public function permissionable(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get audit logs for this permission
     */
    public function auditLogs(): MorphMany
    {
        return $this->morphMany(Audit::class, 'auditable');
    }
}

// Model demonstrating deep polymorphic chains with multiple relationships
class Workflow extends Model
{
    protected $fillable = ['name', 'status', 'workflowable_id', 'workflowable_type'];
    
    /**
     * Get the entity this workflow belongs to
     */
    public function workflowable(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get workflow steps
     */
    public function steps(): MorphMany
    {
        return $this->morphMany(WorkflowStep::class, 'steppable');
    }
    
    /**
     * Get notifications for this workflow
     */
    public function notifications(): MorphMany
    {
        return $this->morphMany(Notification::class, 'subject');
    }
    
    /**
     * Get activities for this workflow
     */
    public function activities(): MorphMany
    {
        return $this->morphMany(ActivityLog::class, 'subject');
    }
}

// Model for workflow steps (continuing the chain)
class WorkflowStep extends Model
{
    protected $fillable = ['name', 'status', 'config', 'steppable_id', 'steppable_type'];
    
    protected $casts = [
        'config' => 'array',
    ];
    
    /**
     * Get the parent steppable (Workflow, Pipeline, etc.)
     */
    public function steppable(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get activities for this step
     */
    public function activities(): MorphMany
    {
        return $this->morphMany(ActivityLog::class, 'subject');
    }
    
    /**
     * Get step attachments
     */
    public function attachments(): MorphMany
    {
        return $this->morphMany(Attachment::class, 'attachable');
    }
}

// Model demonstrating polymorphic relationships with complex business logic
class Invoice extends Model
{
    protected $fillable = ['number', 'amount', 'status', 'billable_id', 'billable_type'];
    
    /**
     * Get the billable entity (User, Company, Project, etc.)
     */
    public function billable(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get invoice line items (polymorphic to different product types)
     */
    public function lineItems(): MorphMany
    {
        return $this->morphMany(InvoiceLineItem::class, 'lineable');
    }
    
    /**
     * Get payments for this invoice
     */
    public function payments(): MorphMany
    {
        return $this->morphMany(Payment::class, 'payable');
    }
    
    /**
     * Get audit trail
     */
    public function audits(): MorphMany
    {
        return $this->morphMany(Audit::class, 'auditable');
    }
}

// Model for invoice line items (part of complex polymorphic chain)
class InvoiceLineItem extends Model
{
    protected $fillable = ['description', 'quantity', 'unit_price', 'lineable_id', 'lineable_type', 'product_id', 'product_type'];
    
    /**
     * Get the parent lineable (Invoice, Quote, Order, etc.)
     */
    public function lineable(): MorphTo
    {
        return $this->morphTo();
    }
    
    /**
     * Get the product this line item represents (polymorphic to different product types)
     */
    public function product(): MorphTo
    {
        return $this->morphTo();
    }
}