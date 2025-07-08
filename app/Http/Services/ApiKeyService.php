<?php 

namespace App\Http\Services;
 
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail; 
use App\Models\ApiKeys;

class ApiKeyService
{
    public function createKeyPair($user, $company, array $data = []): array
    {
        return DB::transaction(function () use ($user, $company, $data) {
            $keyData = ApiKeys::generateKeyPair(
                $user->id, 
                $company->id, 
                $data['environment'] ?? 'test'
            );

            // Créer la clé privée
            $privateApiKey = ApiKeys::create(array_merge($keyData, [
                'key_type' => 'private',
                'name' => $data['name'] ?? 'Clé privée par défaut',
                'description' => $data['description'] ?? null,
                'permissions' => $data['permissions'] ?? $this->getDefaultPermissions(),
                'created_by' => $user->id,
            ]));

            // Créer la clé publique correspondante
            $publicKeyData = $keyData;
            $publicKeyData['public_key'] = str_replace('sk_', 'pk_', $keyData['private_key']);
            $publicKeyData['key_hash'] = bcrypt($publicKeyData['public_key']);
            $publicKeyData['key_type'] = 'public';
            $publicKeyData['name'] = $data['name'] ?? 'Clé publique par défaut';

            $publicApiKey = ApiKeys::create($publicKeyData);

            // Envoyer les clés par email (une seule fois)
            try {
                // Mail::to($user->email)->send(new ApiKeyCreated([
                //     'user' => $user,
                //     'company' => $company,
                //     'public_key' => $publicKeyData['public_key'],
                //     'private_key' => $keyData['private_key'], // Attention: sensible!
                //     'environment' => $keyData['environment']
                // ]));
            } catch (\Exception $e) {
                Log::error('Failed to send API key email', [
                    'user_id' => $user->id,
                    'error' => $e->getMessage()
                ]);
            }

            return [
                'private_key' => $privateApiKey,
                'public_key' => $publicApiKey,
                'credentials' => [
                    'public_key' => $publicKeyData['public_key'],
                    'private_key' => $keyData['private_key'], // Retourné une seule fois
                    'environment' => $keyData['environment']
                ]
            ];
        });
    }

    public function revokeKey(string $keyId, $revokedBy, string $reason = null): bool
    {
        $apiKey = ApiKeys::where('key_id', $keyId)->first();
        
        if (!$apiKey || $apiKey->status === 'revoked') {
            return false;
        }

        $apiKey->update([
            'status' => 'revoked',
            'revoked_at' => now(),
            'revoked_by' => $revokedBy->id,
            'revocation_reason' => $reason
        ]);

        // Invalider le cache
        Cache::forget("api_key:{$keyId}");

        Log::info('API Key revoked', [
            'key_id' => $keyId,
            'revoked_by' => $revokedBy->id,
            'reason' => $reason
        ]);

        return true;
    }

    public function validateKey(string $keyValue): ?ApiKeys
    {
        // Extraire l'ID de la clé depuis le format
        if (!preg_match('/^(pk|sk)_(test|live|sandbox)_(.+)$/', $keyValue, $matches)) {
            return null;
        }

        $environment = $matches[2];
        $cacheKey = "api_key:" . hash('sha256', $keyValue);

        return Cache::remember($cacheKey, 3600, function () use ($keyValue, $environment) {
            return ApiKeys::where('environment', $environment)
                ->where('status', 'active')
                ->get()
                ->first(function ($apiKey) use ($keyValue) {
                    return $apiKey->verifyKey($keyValue);
                });
        });
    }

    private function getDefaultPermissions(): array
    {
        return [
            'payments' => [
                'create' => true,
                'read' => true,
                'update' => false,
                'cancel' => true
            ],
            'refunds' => [
                'create' => true,
                'read' => true
            ],
            'webhooks' => [
                'manage' => false
            ],
            'reports' => [
                'access' => true,
                'export' => false
            ],
            'limits' => [
                'max_amount_per_transaction' => 100000, // En centimes
                'max_amount_per_day' => 1000000,
                'allowed_currencies' => ['XAF', 'EUR', 'USD']
            ]
        ];
    }
}