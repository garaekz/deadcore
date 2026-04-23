<?php

declare(strict_types=1);

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

final class ShowPolicyPostRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'ready' => ['sometimes', 'boolean'],
            'present' => ['sometimes', 'boolean'],
        ];
    }
}
