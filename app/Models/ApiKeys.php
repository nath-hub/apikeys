<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class ApiKeys extends Model
{
    use HasFactory;

    protected $fillable = [
        'key_id',
        'key_hash',  
         
    ];
     protected $casts = [
        'permissions' => 'array',
        'ip_whitelist' => 'array',
        'domain_whitelist' => 'array',
        'expires_at' => 'datetime',
        'last_used_at' => 'datetime',
        'revoked_at' => 'datetime',
    ];

    //  protected $hidden = ['key_hash'];

      public function isActive(): bool
    {
        return $this->status === 'active' && 
               ($this->expires_at === null || $this->expires_at->isFuture());
    }

    public function verifyKey(string $key): bool
    {
        return Hash::check($key, $this->key_hash);
    }

     public function updateUsage(string $ip = null): void
    {
        $this->increment('usage_count');
        $this->update([
            'last_used_at' => now(),
            'last_used_ip' => $ip
        ]);
    }

    public static function generateKeyPair(int $userId, int $companyId, string $environment = 'test'): array
    {
        $publicSuffix = Str::random(32);
        $privateSuffix = Str::random(64);
        
        $publicKey = "pk_{$environment}_{$publicSuffix}";
        $privateKey = "sk_{$environment}_{$privateSuffix}";
        
        return [
            'key_id' => Str::random(32),
            'public_key' => $publicKey,
            'private_key' => $privateKey,
            'key_hash' => Hash::make($privateKey),
            'user_id' => $userId,
            'company_id' => $companyId,
            'environment' => $environment,
            'key_type' => 'private' // On crée d'abord la clé privée
        ];
    }
}
