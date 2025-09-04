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
            $environment = $data['environment'] ?? 'test';
            $permissions = $data['permissions'] ?? $this->getDefaultPermissions();
            $ipWhitelist = $data['ip_whitelist'] ?? null;

            // Vérifier s'il existe déjà une paire de clés avec les mêmes caractéristiques
            $existingKeys = $this->findExistingKeyPair($user->id, $company['id'], $environment, $permissions, $ipWhitelist);

            if ($existingKeys['exists']) {
                // Régénérer les clés existantes
                return $this->regenerateExistingKeys($existingKeys['keys'], $user, $company, $data);
            } else {
                // Créer une nouvelle paire de clés
                return $this->createNewKeyPair($user, $company, $data);
            }
        });
    }



    private function findExistingKeyPair($userId, $companyId, $environment, $permissions, $ipWhitelist): array
    {
        $existingKeys = ApiKeys::where('user_id', $userId)
            ->where('entreprise_id', $companyId)
            ->where('environment', $environment)
            ->where('status', 'active')
            ->whereNull('revoked_at')
            ->where(function ($query) {
                $query->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            })
            ->get();

        // Vérifier si on a une paire complète (public + private) avec les mêmes permissions
        $publicKey = $existingKeys->where('key_type', 'public')->first();
        $privateKey = $existingKeys->where('key_type', 'private')->first();

        if ($publicKey && $privateKey) {
            // Comparer les permissions et IP whitelist
            $samePermissions = $this->comparePermissions($publicKey->permissions, $permissions);
            $sameIpWhitelist = $this->compareIpWhitelist($publicKey->ip_whitelist, $ipWhitelist);

            if ($samePermissions && $sameIpWhitelist) {
                return [
                    'exists' => true,
                    'keys' => [
                        'public' => $publicKey,
                        'private' => $privateKey
                    ]
                ];
            }
        }

        return ['exists' => false, 'keys' => null];
    }



    private function comparePermissions($existing, $new): bool
    {
        if (is_string($existing)) {
            $existing = json_decode($existing, true);
        }
        if (is_string($new)) {
            $new = json_decode($new, true);
        }

        // Trier les tableaux pour une comparaison correcte
        sort($existing);
        sort($new);

        return $existing === $new;
    }

    /**
     * Compare deux listes d'IPs whitelist
     */
    private function compareIpWhitelist($existing, $new): bool
    {
        if (is_string($existing)) {
            $existing = json_decode($existing, true);
        }
        if (is_string($new)) {
            $new = json_decode($new, true);
        }

        // Si les deux sont null ou vides, considérer comme identiques
        if (empty($existing) && empty($new)) {
            return true;
        }

        // Trier et comparer
        if ($existing && $new) {
            sort($existing);
            sort($new);
            return $existing === $new;
        }

        return false;
    }



    private function regenerateExistingKeys($existingKeys, $user, $company, array $data): array
    {
        $publicKey = $existingKeys['public'];
        $privateKey = $existingKeys['private'];

        // Générer de nouvelles clés
        $newKeyData = ApiKeys::generateKeyPair(
            $user->id,
            $company['id'],
            $data['environment'] ?? 'test'
        );

        // Mettre à jour la clé privée
        $privateKey->update([
            'key_id' => $newKeyData['private_key'],
            'key_hash' => $newKeyData['key_hash'],
            'name' => $data['name'] ?? $privateKey->name,
            'description' => $data['description'] ?? $privateKey->description,
            'permissions' => $data['permissions'] ?? $privateKey->permissions,
            'ip_whitelist' => $data['ip_whitelist'] ?? $privateKey->ip_whitelist,
            'updated_at' => now(),
            'last_used_at' => null, // Reset car nouvelle clé
            'usage_count' => 0, // Reset car nouvelle clé
        ]);

        // Mettre à jour la clé publique
        $publicKey->update([
            'key_id' => $newKeyData['public_key'],
            'key_hash' => $newKeyData['key_hash'],
            'name' => $data['name'] ?? $publicKey->name,
            'description' => $data['description'] ?? $publicKey->description,
            'permissions' => $data['permissions'] ?? $publicKey->permissions,
            'ip_whitelist' => $data['ip_whitelist'] ?? $publicKey->ip_whitelist,
            'updated_at' => now(),
            'last_used_at' => null, // Reset car nouvelle clé
            'usage_count' => 0, // Reset car nouvelle clé
        ]);

        // Log de la régénération
        Log::info('API Keys regenerated', [
            'user_id' => $user->id,
            'company_id' => $company['id'],
            'environment' => $data['environment'] ?? 'test',
            'private_key_id' => $privateKey->id,
            'public_key_id' => $publicKey->id,
        ]);

        // Envoyer un email de notification pour la régénération
        $this->sendKeyRegeneratedNotification($user, $company, $newKeyData);

        return [
            'regenerated' => true,
            'private_key' => $privateKey->fresh(),
            'public_key' => $newKeyData['public_key'],
            'credentials' => [
                'public_key' => $newKeyData['public_key'],
                'private_key' => $newKeyData['private_key'],
                'environment' => $newKeyData['environment']
            ]
        ];
    }


    private function createNewKeyPair($user, $company, array $data): array
    {
        $keyData = ApiKeys::generateKeyPair(
            $user->id,
            $company['id'],
            $data['environment'] ?? 'test'
        );

        $expiresAt = now()->addYears(2); // date d’expiration à 2 ans

        $privateApiKey = ApiKeys::create([
            'key_hash' => $keyData['key_hash'],
            'entreprise_id' => $company['id'],
            'environment' => $keyData['environment'],
            'ip_whitelist' => $data['ip_whitelist'] ?? null,
            'key_id' => $keyData['private_key'],
            'key_type' => 'private',
            'name' => $data['name'] ?? 'Clé privée par défaut',
            'description' => $data['description'] ?? null,
            'permissions' => $data['permissions'] ?? $this->getDefaultPermissions(),
            'created_by' => $user->id,
            'user_id' => $user->id,
            'expires_at' => $expiresAt,
        ]);

        $publicKeyData = ApiKeys::create([
            'key_hash' => $keyData['key_hash'],
            'entreprise_id' => $company['id'],
            'environment' => $keyData['environment'],
            'ip_whitelist' => $data['ip_whitelist'] ?? null,
            'key_id' => $keyData['public_key'],
            'key_type' => 'public',
            'name' => $data['name'] ?? 'Clé publique par défaut',
            'description' => $data['description'] ?? null,
            'permissions' => $data['permissions'] ?? $this->getDefaultPermissions(),
            'created_by' => $user->id,
            'user_id' => $user->id,
            'expires_at' => $expiresAt,
        ]);

        // Envoyer les clés par email (une seule fois)
        $this->sendKeyCreatedNotification($user, $company, $keyData);

        return [
            'regenerated' => false,
            'private_key' => $privateApiKey,
            'public_key' => $keyData['public_key'],
            'credentials' => [
                'public_key' => $keyData['public_key'],
                'private_key' => $keyData['private_key'],
                'environment' => $keyData['environment']
            ]
        ];
    }

    /**
     * Envoie une notification pour la création de nouvelles clés
     */
    private function sendKeyCreatedNotification($user, $company, $keyData): void
    {
        try {
            // Mail::to($user->email)->send(new ApiKeyCreated([
            //     'user' => $user,
            //     'company' => $company,
            //     'public_key' => $keyData['public_key'],
            //     'private_key' => $keyData['private_key'],
            //     'environment' => $keyData['environment']
            // ]));
        } catch (\Exception $e) {
            Log::error('Failed to send API key creation email', [
                'user_id' => $user->id,
                'error' => $e->getMessage()
            ]);
        }
    }




    private function sendKeyRegeneratedNotification($user, $company, $keyData): void
    {
        try {
            // Mail::to($user->email)->send(new ApiKeyRegenerated([
            //     'user' => $user,
            //     'company' => $company,
            //     'public_key' => $keyData['public_key'],
            //     'private_key' => $keyData['private_key'],
            //     'environment' => $keyData['environment']
            // ]));
        } catch (\Exception $e) {
            Log::error('Failed to send API key regeneration email', [
                'user_id' => $user->id,
                'error' => $e->getMessage()
            ]);
        }
    }


    public function revokeKey(string $keyId, $revokedBy, string $reason, $apiKey): bool
    { 
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


     public function updateKeyUsage(string $keyId, string $ipAddress, ?string $domain = null, array $updateData = []): bool
    {
        try {
            $apiKey = ApiKeys::where('id', $keyId)
                ->where('status', 'active')
                ->whereNull('revoked_at')
                ->first();

            if (!$apiKey) {
                Log::warning('Tentative d\'utilisation d\'une clé API inexistante ou inactive', [
                    'key_id' => $keyId,
                    'ip' => $ipAddress
                ]);
                return false;
            }

            // Vérifier si la clé a expiré
            if ($apiKey->expires_at && $apiKey->expires_at->isPast()) {
                $this->expireKey($apiKey);
                return false;
            }

            // Préparer les données de mise à jour
            $updateFields = [
                'last_used_at' => now(),
                'last_used_ip' => $ipAddress,
                'usage_count' => DB::raw('usage_count + 1'),
                'updated_at' => now()
            ];

            // Gestion de la whitelist IP
            if (!empty($ipAddress)) {
                $currentIpWhitelist = $apiKey->ip_whitelist ? 
                    (is_array($apiKey->ip_whitelist) ? $apiKey->ip_whitelist : json_decode($apiKey->ip_whitelist, true)) : 
                    [];
                
                if (!in_array($ipAddress, $currentIpWhitelist)) {
                    $currentIpWhitelist[] = $ipAddress;
                    $updateFields['ip_whitelist'] = json_encode(array_unique($currentIpWhitelist));
                }
            }

            // Gestion de la whitelist de domaines
            if (!empty($domain)) {
                $currentDomainWhitelist = $apiKey->domain_whitelist ? 
                    (is_array($apiKey->domain_whitelist) ? $apiKey->domain_whitelist : json_decode($apiKey->domain_whitelist, true)) : 
                    [];
                
                if (!in_array($domain, $currentDomainWhitelist)) {
                    $currentDomainWhitelist[] = $domain;
                    $updateFields['domain_whitelist'] = json_encode(array_unique($currentDomainWhitelist));
                }
            }

            // Ajouter les données personnalisées
            if (!empty($updateData)) {
                // Vérifier que les champs sont autorisés
                $allowedFields = ['rate_limit_per_minute', 'permissions', 'description'];
                foreach ($updateData as $field => $value) {
                    if (in_array($field, $allowedFields)) {
                        $updateFields[$field] = $value;
                    }
                }
            }

            // Mettre à jour la clé
            $updated = $apiKey->update($updateFields);

            if ($updated) {
                Log::info('Utilisation de clé API mise à jour', [
                    'key_id' => $keyId,
                    'ip' => $ipAddress,
                    'domain' => $domain, 
                ]);
            }

            return $updated;

        } catch (\Exception $e) {
            Log::error('Erreur lors de la mise à jour de l\'utilisation de la clé API', [
                'key_id' => $keyId,
                'ip' => $ipAddress,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            return false;
        }
    }


     /**
     * Expire une clé API spécifique
     * 
     * @param ApiKeys|string $key Instance de la clé ou key_id
     * @return bool
     */
    public function expireKey($key): bool
    {
        try {
            if (is_string($key)) {
                $key = ApiKeys::where('key_id', $key)->first();
                if (!$key) {
                    return false;
                }
            }

            $updated = $key->update([
                'status' => 'expired',
                'revoked_at' => now(),
                'revocation_reason' => 'Clé expirée automatiquement',
                'updated_at' => now()
            ]);

            if ($updated) {
                Log::info('Clé API expirée', [
                    'key_id' => $key->key_id,
                    'user_id' => $key->user_id,
                    'entreprise_id' => $key->entreprise_id,
                    'expires_at' => $key->expires_at,
                    'expired_at' => now()
                ]);

                // Optionnel : Envoyer une notification à l'utilisateur
                $this->notifyKeyExpired($key);
            }

            return $updated;

        } catch (\Exception $e) {
            Log::error('Erreur lors de l\'expiration de la clé API', [
                'key_id' => is_object($key) ? $key->key_id : $key,
                'error' => $e->getMessage()
            ]);
            return false;
        }
    }

    /**
     * Vérifie si une clé peut être utilisée (rate limiting)
     * 
     * @param string $keyId
     * @return array
     */
    public function checkRateLimit(string $keyId): array
    {
        try {
            $apiKey = ApiKeys::where('key_id', $keyId)
                ->where('status', 'active')
                ->first();

            if (!$apiKey) {
                return [
                    'allowed' => false,
                    'reason' => 'Clé inexistante ou inactive'
                ];
            }

            // Vérifier l'expiration
            if ($apiKey->expires_at && $apiKey->expires_at->isPast()) {
                $this->expireKey($apiKey);
                return [
                    'allowed' => false,
                    'reason' => 'Clé expirée'
                ];
            }

            // Vérifier le rate limit (exemple simple basé sur la minute courante)
            $currentMinute = now()->format('Y-m-d H:i');
            $cacheKey = "api_rate_limit:{$keyId}:{$currentMinute}";
            
            $currentRequests = cache()->get($cacheKey, 0);
            
            if ($currentRequests >= $apiKey->rate_limit_per_minute) {
                return [
                    'allowed' => false,
                    'reason' => 'Rate limit dépassé',
                    'limit' => $apiKey->rate_limit_per_minute,
                    'current' => $currentRequests,
                    'reset_at' => now()->addMinute()->startOfMinute()
                ];
            }

            // Incrémenter le compteur
            cache()->put($cacheKey, $currentRequests + 1, 60);

            return [
                'allowed' => true,
                'remaining' => $apiKey->rate_limit_per_minute - $currentRequests - 1,
                'limit' => $apiKey->rate_limit_per_minute
            ];

        } catch (\Exception $e) {
            Log::error('Erreur lors de la vérification du rate limit', [
                'key_id' => $keyId,
                'error' => $e->getMessage()
            ]);

            return [
                'allowed' => false,
                'reason' => 'Erreur système'
            ];
        }
    }


      /**
     * Vérifie et expire les clés qui ont dépassé leur date d'expiration
     * 
     * @param string|null $keyId Clé spécifique à vérifier (optionnel)
     * @return array Statistiques des clés expirées
     */
    public function checkAndExpireKeys(?string $keyId = null): array
    {
        try {
            $query = ApiKeys::where('status', 'active')
                ->whereNotNull('expires_at')
                ->where('expires_at', '<=', now());

            if ($keyId) {
                $query->where('key_id', $keyId);
            }

            $expiredKeys = $query->get();
            $expiredCount = 0;
            $errors = [];

            foreach ($expiredKeys as $key) {
                try {
                    $this->expireKey($key);
                    $expiredCount++;
                } catch (\Exception $e) {
                    $errors[] = [
                        'key_id' => $key->key_id,
                        'error' => $e->getMessage()
                    ];
                }
            }

            $result = [
                'total_checked' => $expiredKeys->count(),
                'expired_count' => $expiredCount,
                'errors' => $errors
            ];

            Log::info('Vérification d\'expiration des clés API', $result);

            return $result;

        } catch (\Exception $e) {
            Log::error('Erreur lors de la vérification des clés expirées', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            return [
                'total_checked' => 0,
                'expired_count' => 0,
                'errors' => [['general_error' => $e->getMessage()]]
            ];
        }
    }


     /**
     * Nettoie les anciennes entrées de cache de rate limiting
     */
    public function cleanupRateLimitCache(): void
    {
        try {
            // Cette méthode dépend de votre driver de cache
            // Pour Redis par exemple :
            if (config('cache.default') === 'redis') {
                $redis = app('redis');
                $keys = $redis->keys('api_rate_limit:*');
                
                foreach ($keys as $key) {
                    $parts = explode(':', $key);
                    if (count($parts) >= 3) {
                        $timestamp = end($parts);
                        if (strtotime($timestamp) < strtotime('-2 minutes')) {
                            $redis->del($key);
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            Log::error('Erreur lors du nettoyage du cache rate limit', [
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * Envoie une notification d'expiration de clé (à implémenter selon vos besoins)
     */
    private function notifyKeyExpired(ApiKeys $key): void
    {
        try {
            // Exemple d'implémentation
            // Mail::to($key->user->email)->send(new ApiKeyExpired($key));
            
            Log::info('Notification d\'expiration de clé envoyée', [
                'key_id' => $key->key_id,
                'user_id' => $key->user_id
            ]);
        } catch (\Exception $e) {
            Log::error('Erreur lors de l\'envoi de notification d\'expiration', [
                'key_id' => $key->key_id,
                'error' => $e->getMessage()
            ]);
        }
    }

    /**
     * Statistiques d'utilisation d'une clé
     */
    public function getKeyUsageStats(string $keyId): array
    {
        try {
            $apiKey = ApiKeys::where('key_id', $keyId)->first();
            
            if (!$apiKey) {
                return ['error' => 'Clé non trouvée'];
            }

            return [
                'key_id' => $keyId,
                'usage_count' => $apiKey->usage_count,
                'last_used_at' => $apiKey->last_used_at,
                'last_used_ip' => $apiKey->last_used_ip,
                'rate_limit_per_minute' => $apiKey->rate_limit_per_minute,
                'status' => $apiKey->status,
                'expires_at' => $apiKey->expires_at,
                'ip_whitelist' => $apiKey->ip_whitelist,
                'domain_whitelist' => $apiKey->domain_whitelist,
                'days_until_expiry' => $apiKey->expires_at ? 
                    now()->diffInDays($apiKey->expires_at, false) : null
            ];
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }

}