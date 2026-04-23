<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class UpdateProductRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     */
    public function rules(): array
    {
        return [
            'name' => 'sometimes|required|string|max:255',
            'description' => 'sometimes|required|string',
            'price' => 'sometimes|required|numeric|min:0',
            'category_id' => 'sometimes|required|exists:categories,id',
            'sku' => [
                'sometimes',
                'required',
                'string',
                Rule::unique('products')->ignore($this->product)
            ],
            'stock_quantity' => 'sometimes|required|integer|min:0',
            'is_active' => 'boolean',
            'tags' => 'array',
            'tags.*' => 'exists:tags,id',
        ];
    }
}