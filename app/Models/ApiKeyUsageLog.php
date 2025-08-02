<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

class ApiKeyUsageLog extends Model
{
    use HasFactory;

    public $incrementing = false;

    protected $keyType = 'string';
    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $guarded = [
        'id'
    ];

    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            if (empty($model->id)) {
                $model->id = (string) Str::uuid();
            }
        });
    }


    protected $casts = [
        'created_at' => 'datetime',
        'processed_at' => 'datetime',
        'signature_valid' => 'boolean',
        'is_suspicious' => 'boolean',
        'request_headers' => 'array',
        'amount' => 'decimal:2',
        'latitude' => 'decimal:8',
        'longitude' => 'decimal:8'
    ];

    // Désactiver updated_at car on ne modifie jamais les logs
    public $timestamps = false;
    protected $dates = ['created_at', 'processed_at'];

    // ============================================
    // RELATIONS
    // ============================================

    public function apiKey()
    {
        return $this->belongsTo(ApiKeys::class);
    }

    public function user()
    {
        return $this->belongsTo(User::class);
    }

    // ============================================
    // SCOPES
    // ============================================

    public function scopeByUser(Builder $query, string $userId): Builder
    {
        return $query->where('user_id', $userId);
    }

    // public function scopeByApiKey(Builder $query, string $apiKeyId): Builder
    // {
    //     return $query->where('api_key_id', $apiKeyId);
    // }

    public function scopeByAction(Builder $query, string $action): Builder
    {
        return $query->where('action', $action);
    }

    public function scopeByEnvironment(Builder $query, string $environment)
    {
        return $query->where('environment', $environment);
    }

    public function scopeByStatus(Builder $query, string $status): Builder
    {
        return $query->where('status', $status);
    }

    public function scopeSuspicious(Builder $query): Builder
    {
        return $query->where('is_suspicious', true);
    }

    public function scopeSuccessful(Builder $query): Builder
    {
        return $query->where('status', 'success');
    }

    public function scopeFailed(Builder $query): Builder
    {
        return $query->where('status', 'failed');
    }

    public function scopeToday(Builder $query): Builder
    {
        return $query->whereDate('created_at', today());
    }

    public function scopeThisWeek(Builder $query): Builder
    {
        return $query->whereBetween('created_at', [
            now()->startOfWeek(),
            now()->endOfWeek()
        ]);
    }

    public function scopeThisMonth(Builder $query): Builder
    {
        return $query->whereMonth('created_at', now()->month)
            ->whereYear('created_at', now()->year);
    }

    public function scopeDateRange(Builder $query, Carbon $startDate, Carbon $endDate): Builder
    {
        return $query->whereBetween('created_at', [$startDate, $endDate]);
    }

    public function scopeByCountry(Builder $query, string $countryCode): Builder
    {
        return $query->where('country_code', $countryCode);
    }

    public function scopeSlowRequests(Builder $query, int $thresholdMs = 5000): Builder
    {
        return $query->where('response_time_ms', '>', $thresholdMs);
    }

    public function scopeFinancialTransactions(Builder $query): Builder
    {
        return $query->whereNotNull('amount');
    }


    // ============================================
    // MÉTHODES UTILITAIRES
    // ============================================

    /**
     * Marque ce log comme suspect
     */
    public function markAsSuspicious(?string $reason): void
    {
        $this->update([
            'is_suspicious' => true,
            'error_message' => $reason ? "Suspicious activity: {$reason}" : 'Suspicious activity detected'
        ]);
    }

    /**
     * Calcule le temps de réponse en format lisible
     */
    public function getFormattedResponseTimeAttribute(): string
    {
        if (!$this->response_time_ms) {
            return 'N/A';
        }

        if ($this->response_time_ms < 1000) {
            return $this->response_time_ms . 'ms';
        }

        return round($this->response_time_ms / 1000, 2) . 's';
    }

    /**
     * Retourne une représentation lisible du statut
     */
    public function getStatusBadgeAttribute(): string
    {
        return match ($this->status) {
            'success' => '✅ Success',
            'failed' => '❌ Failed',
            'blocked' => '🚫 Blocked',
            'rate_limited' => '⚠️ Rate Limited',
            default => '❓ Unknown'
        };
    }

    /**
     * Vérifie si c'est une transaction financière
     */
    public function isFinancialTransaction(): bool
    {
        return !is_null($this->amount) && $this->amount > 0;
    }

    /**
     * Retourne les headers filtrés (sans données sensibles)
     */
    public function getSafeHeaders(): array
    {
        if (!$this->request_headers) {
            return [];
        }

        $sensitiveHeaders = [
            'x-api-private-key',
            'x-api-signature',
            'authorization',
            'cookie',
            'x-forwarded-for'
        ];

        return array_filter($this->request_headers, function ($key) use ($sensitiveHeaders) {
            return !in_array(strtolower($key), $sensitiveHeaders);
        }, ARRAY_FILTER_USE_KEY);
    }
}
