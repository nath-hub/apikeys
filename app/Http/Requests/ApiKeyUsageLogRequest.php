<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class ApiKeyUsageLogRequest extends FormRequest
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
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
     public function rules(): array
    {
        return [
            'user_id' => 'nullable|uuid',
            'public_key_id' => 'string|max:255',
            'private_key_id' => 'string|max:255',
            'action' => 'nullable|string|max:255',
            'endpoint' => 'nullable|string|max:500',
            'http_method' => 'required|string|in:GET,POST,PUT,DELETE,PATCH,OPTIONS,HEAD',
            'request_uuid' => 'nullable|uuid',
            'request_id' => 'nullable|string|max:255',
            'ip_address' => 'required|ip',
            'user_agent' => 'nullable|string|max:1000',
            'country_code' => 'nullable|string',
            'environment' => 'required|string|in:prod,sandbox',
            'response_time_ms' => 'nullable|integer|min:0|max:300000', // Max 5 minutes
            'response_status_code' => 'nullable|integer|min:100|max:599',
            'request_size_bytes' => 'nullable|integer|min:0',
            'response_size_bytes' => 'nullable|integer|min:0',
            'signature_valid' => 'boolean',
            'source_service' => 'nullable|string|max:100',
            'request_headers' => 'nullable|array',
            'amount' => 'nullable|numeric|min:0|max:999999999.99',
            'currency' => 'nullable|string|size:3',
            'status' => 'required|string|in:success,failed,blocked,rate_limited',
            'is_suspicious' => 'boolean',
            'error_message' => 'nullable|string|max:1000',
            'error_code' => 'nullable|string|max:100',
            'city' => 'nullable|string|max:100',
            'region' => 'nullable|string|max:100',
            'latitude' => 'nullable|numeric|between:-90,90',
            'longitude' => 'nullable|numeric|between:-180,180'
        ];
    }

    public function messages(): array
    {
        return [
            // 'api_key_id.exists' => 'The specified API key does not exist.',
            // 'user_id.exists' => 'The specified user does not exist.',
            'ip_address.ip' => 'Please provide a valid IP address.',
            'request_uuid.uuid' => 'The request UUID must be a valid UUID format.',
            'currency.size' => 'Currency code must be exactly 3 characters (e.g., XAF, EUR, USD).',
            'latitude.between' => 'Latitude must be between -90 and 90 degrees.',
            'longitude.between' => 'Longitude must be between -180 and 180 degrees.',
            'response_time_ms.max' => 'Response time cannot exceed 5 minutes (300000ms).'
        ];
    }
}
