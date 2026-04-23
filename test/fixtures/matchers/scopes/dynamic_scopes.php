<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

class Product extends Model
{
    protected $fillable = [
        'name', 'price', 'category', 'status', 'featured',
        'in_stock', 'discount_percentage', 'brand', 'color'
    ];

    /**
     * Dynamic scope calls that should be detected.
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->where('status', 'active');
    }

    public function scopeFeatured(Builder $query): Builder
    {
        return $query->where('featured', true);
    }

    public function scopeInStock(Builder $query): Builder
    {
        return $query->where('in_stock', true);
    }

    public function scopeOnSale(Builder $query): Builder
    {
        return $query->where('discount_percentage', '>', 0);
    }

    public function scopeByCategory(Builder $query, string $category): Builder
    {
        return $query->where('category', $category);
    }

    public function scopeByBrand(Builder $query, string $brand): Builder
    {
        return $query->where('brand', $brand);
    }

    public function scopePriceRange(Builder $query, float $min, float $max): Builder
    {
        return $query->whereBetween('price', [$min, $max]);
    }
}

class ProductController
{
    public function index(Request $request)
    {
        $query = Product::query();

        // Dynamic scope usage patterns
        $products = Product::active()->featured()->get();
        $inStockProducts = Product::inStock()->active()->get();
        
        // Whereable patterns (should be detected with lower confidence)
        $activeProducts = Product::whereActive(true)->get();
        $featuredProducts = Product::whereFeatured(true)->get();
        $categoryProducts = Product::whereCategory('electronics')->get();
        
        // Complex dynamic queries
        if ($request->filled('featured')) {
            $query->featured();
        }
        
        if ($request->filled('category')) {
            $query->byCategory($request->category);
        }
        
        if ($request->filled('brand')) {
            $query->byBrand($request->brand);
        }
        
        if ($request->filled('min_price') && $request->filled('max_price')) {
            $query->priceRange($request->min_price, $request->max_price);
        }
        
        if ($request->filled('in_stock')) {
            $query->inStock();
        }
        
        if ($request->filled('on_sale')) {
            $query->onSale();
        }
        
        $results = $query->active()->paginate(20);
        
        return response()->json($results);
    }
    
    public function search(Request $request)
    {
        // Chained scope calls
        $products = Product::query()
            ->when($request->featured, fn($q) => $q->featured())
            ->when($request->category, fn($q) => $q->byCategory($request->category))
            ->when($request->in_stock, fn($q) => $q->inStock())
            ->active()
            ->get();
            
        // Alternative dynamic calls
        $alternativeQuery = Product::active();
        
        if ($request->has('featured')) {
            $alternativeQuery = $alternativeQuery->featured();
        }
        
        $results = $alternativeQuery->get();
        
        return compact('products', 'results');
    }
}