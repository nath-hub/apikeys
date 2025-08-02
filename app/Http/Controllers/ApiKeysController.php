<?php

namespace App\Http\Controllers;

use App\Models\ApiKeys;
use App\Http\Controllers\Controller;
use App\Http\Services\ApiKeyService;
use App\Http\Services\UserService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;

/**
 * @OA\Tag(
 *     name="API Keys",
 *     description="Gestion des clés API pour l'authentification"
 * )
 */
class ApiKeysController extends Controller
{

    public function __construct(private ApiKeyService $apiKeyService, private UserService $userService)
    {
    }


    /**
     * @OA\Get(
     *     path="/api/apikeys",
     *     tags={"API Keys"},
     *     summary="Lister les clés API de l'utilisateur",
     *     description="Récupère toutes les clés API de l'utilisateur connecté (sans les valeurs des clés privées)",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="environment",
     *         in="query",
     *         description="Filtrer par environnement",
     *         @OA\Schema(type="string", enum={"test", "live", "sandbox"})
     *     ),
     *     @OA\Parameter(
     *         name="status",
     *         in="query",
     *         description="Filtrer par statut",
     *         @OA\Schema(type="string", enum={"active", "inactive", "revoked", "expired"})
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Liste des clés API",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Clés API récupérées"),
     *             @OA\Property(
     *                 property="data",
     *                 type="array",
     *                 @OA\Items(
     *                     @OA\Property(property="id", type="integer"),
     *                     @OA\Property(property="key_id", type="string"),
     *                     @OA\Property(property="name", type="string"),
     *                     @OA\Property(property="key_type", type="string"),
     *                     @OA\Property(property="environment", type="string"),
     *                     @OA\Property(property="status", type="string"),
     *                     @OA\Property(property="last_used_at", type="string", format="date-time"),
     *                     @OA\Property(property="usage_count", type="integer"),
     *                     @OA\Property(property="created_at", type="string", format="date-time"),
     *                     @OA\Property(property="masked_key", type="string", example="pk_test_****...****3456")
     *                 )
     *             )
     *         )
     *     )
     * )
     */
    public function index(Request $request)
    {
        $query = ApiKeys::where('user_id', $request->user()->id);

        if ($request->has('environment')) {
            $query->where('environment', $request->environment);
        }

        if ($request->has('status')) {
            $query->where('status', $request->status);
        }

        $apiKeys = $query->orderBy('created_at', 'desc')->get();

        $data = $apiKeys->map(function ($key) {
            return [
                'id' => $key->id,
                'key_id' => $key->key_id,
                'name' => $key->name,
                'key_type' => $key->key_type,
                'environment' => $key->environment,
                'status' => $key->status,
                'last_used_at' => $key->last_used_at,
                'usage_count' => $key->usage_count,
                'created_at' => $key->created_at,
                'expires_at' => $key->expires_at,
                'permissions' => $key->permissions,
            ];
        });

        if ($data) {
            return response()->json([
                'message' => 'Clés API récupérées',
                'data' => $data
            ]);
        } else {
            return response()->json([
                'message' => 'Aucune clés API récupérées'
            ]);
        }


    }

    /**
     * @OA\Post(
     *     path="/api/apikeys/generate",
     *     tags={"API Keys"},
     *     summary="Créer une nouvelle paire de clés API",
     *     description="Génère une paire de clés API (publique/privée) pour l'utilisateur connecté. Les clés sont envoyées par email et retournées dans la réponse (une seule fois).",
     *     security={{"bearerAuth":{}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             @OA\Property(property="name", type="string", example="Clés de production", maxLength=100),
     *             @OA\Property(property="description", type="string", example="Clés pour le site e-commerce principal"),
     *             @OA\Property(property="environment", type="string", enum={"test", "live", "sandbox"}, example="test"),
     *             @OA\Property(
     *                 property="permissions",
     *                 type="object",
     *                 @OA\Property(
     *                     property="payments",
     *                     type="object",
     *                     @OA\Property(property="create", type="boolean", example=true),
     *                     @OA\Property(property="read", type="boolean", example=true),
     *                     @OA\Property(property="cancel", type="boolean", example=false)
     *                 ),
     *                 @OA\Property(
     *                     property="limits",
     *                     type="object",
     *                     @OA\Property(property="max_amount_per_transaction", type="integer", example=50000),
     *                     @OA\Property(property="max_amount_per_day", type="integer", example=500000)
     *                 )
     *             ),
     *             @OA\Property(
     *                 property="ip_whitelist", 
     *                 type="array", 
     *                 @OA\Items(type="string"),
     *                 example={"192.168.1.1", "10.0.0.0/24"}
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Clés API créées avec succès",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Clés API créées avec succès"),
     *             @OA\Property(
     *                 property="data",
     *                 type="object",
     *                 @OA\Property(property="public_key", type="string", example="example_keys"),
     *                 @OA\Property(property="private_key", type="string", example="example_keys"),
     *                 @OA\Property(property="environment", type="string", example="test"),
     *                 @OA\Property(property="created_at", type="string", format="date-time")
     *             ),
     *             @OA\Property(
     *                 property="warning",
     *                 type="string",
     *                 example="⚠️ IMPORTANT: Votre clé privée ne sera plus jamais affichée. Sauvegardez-la maintenant !"
     *             )
     *         )
     *     ),
     *     @OA\Response(response=422, description="Erreur de validation"),
     *     @OA\Response(response=401, description="Non authentifié")
     * )
     */

    public function store(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:100',
            'description' => 'required|string|max:500',
            'environment' => 'required|in:test,live,sandbox',
            'permissions' => 'required|array',
            'ip_whitelist' => 'required|array',
            'ip_whitelist.*' => 'ip',
            'entreprise_id' => 'required|string|exists:entreprises,id'
        ]);

        $user = $request->user();

        $company = $this->userService->getUserCompany(); // Assuming relationship exists

        $result = $this->apiKeyService->createKeyPair($user, $company, $request->all());

        return response()->json([
            'message' => 'Clés API créées avec succès',
            'data' => [
                'public_key' => $result['credentials']['public_key'],
                'private_key' => $result['credentials']['private_key'],
                'environment' => $result['credentials']['environment'],
                'created_at' => $result['private_key']->created_at
            ],
            'warning' => '⚠️ IMPORTANT: Votre clé privée ne sera plus jamais affichée. Sauvegardez-la maintenant !'
        ], 201);
    }


    /**
     * @OA\Delete(
     *     path="/api/apikeys/{id}/delete",
     *     tags={"API Keys"},
     *     summary="Révoquer une clé API",
     *     description="Révoque définitivement une clé API. Cette action est irréversible.",
     *     security={{"bearerAuth":{}}},
     *     @OA\Parameter(
     *         name="keyId",
     *         in="path",
     *         required=true,
     *         description="ID de la clé API à révoquer",
     *         @OA\Schema(type="string")
     *     ),
     *     @OA\RequestBody(
     *         @OA\JsonContent(
     *             @OA\Property(property="reason", type="string", example="Clé compromise")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Clé API révoquée avec succès",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="Clé API révoquée avec succès")
     *         )
     *     ),
     *     @OA\Response(response=404, description="Clé API non trouvée"),
     *     @OA\Response(response=403, description="Non autorisé à révoquer cette clé")
     * )
     */
    public function destroy(Request $request, string $keyId)
    {

        $request->validate([
            'reason' => 'required|string'
        ]);

        $apiKey = ApiKeys::where('id', $keyId)
            // ->where('user_id', $request->user()->id)
            ->first();

        $user = $request->user();

        if ($user->id !== $apiKey->user_id) {
            return response()->json(['message' => 'Vous n\'avez pas le droit de révoquer la clé', 'statut' => 401], 401);

        }

        if (!$apiKey) {
            return response()->json(['message' => 'Clé API non trouvée', 'status' => 404], 404);
        }
 

        $success = $this->apiKeyService->revokeKey(
            $keyId,
            $user,
            $request->input('reason'), $apiKey
        );

        if (!$success) {
            return response()->json(['message' => 'Impossible de révoquer la clé'], 400);
        }

        return response()->json(['message' => 'Clé API révoquée avec succès']);
    }



    public function updateKey(Request $request)
    {

        $request->validate([
            'id' => 'required|string|exists:api_keys,id'
        ]);

        // Récupérer les informations de la requête
        $ipAddress = $request->ip();
        $domain = $request->getHost();


        $result = $this->apiKeyService->updateKeyUsage($request->id, $ipAddress, $domain);

        if ($result) {
            return response()->json(['message' => 'Clé API a jour', 'status' => 200], 200);
        } else {
            return response()->json(['message' => 'Tentative d\'utilisation d\'une clé API inexistante ou inactive', 'status' => 400], 400);
        }

    }


    public function verifyKeys(Request $request)
    {
        $validator = $request->validate([
            'public_key' => 'required|string', //|exists:api_keys,key_id',
            'private_key' => 'required|string',
            'environment' => 'required|in:test,live,sandbox',
            'uuid' => 'required|uuid'
        ]);

        try {
            // 1. Trouver la clé publique
            $publicApiKey = ApiKeys::where('key_id', $request->public_key)
                ->where('key_type', 'public')
                ->where('environment', $request->environment)
                ->where('status', 'active')
                ->first();

            if (!$publicApiKey) {
                return response()->json([
                    'valid' => false,
                    'error' => 'Invalid public key',
                    'code' => 'INVALID_PUBLIC_KEY',
                    'status' => 4001
                ]);
            }

            // 2. Trouver la clé privée correspondante
            $privateApiKey = ApiKeys::where('user_id', $publicApiKey->user_id)
                ->where('key_type', 'private')
                ->where('key_id', $request->private_key)
                ->where('environment', $request->environment)
                ->where('status', 'active')
                ->first();

            if (!$privateApiKey) {
                return response()->json([
                    'valid' => false,
                    'error' => 'Invalid private key',
                    'code' => 'INVALID_PRIVATE_KEY',
                    'status' => 4002
                ]);
            }

            
            // 4. Vérifier les permissions pour l'action demandée
            $permissions = $publicApiKey->permissions ?? $this->getDefaultPermissions();
            
            if ($request->action && !$this->checkActionPermission($permissions, $request->action)) {
                return response()->json([
                    'valid' => false,
                    'error' => 'Action not permitted',
                    'code' => 'ACTION_NOT_PERMITTED',
                    'status' => 403
                ]);
            }

            // 5. Vérifier l'expiration (si applicable)
            if ($publicApiKey->expires_at && $publicApiKey->expires_at->isPast()) {
                // Marquer comme expiré
                $publicApiKey->update(['status' => 'expired']);
                
                return response()->json([
                    'valid' => false,
                    'error' => 'API key expired',
                    'code' => 'KEY_EXPIRED',
                    'status' => 4003
                ]);
            }
             
            // 6. Enregistrer l'utilisation (pour les stats et rate limiting) 

            return response()->json([
                'valid' => true,
                'user_id' => $publicApiKey->user_id,
                'key_id' => $publicApiKey->key_id,
                'permissions' => $permissions,
                'environment' => $publicApiKey->environment,
                'rate_limit_remaining' => $this->getRemainingRateLimit($publicApiKey)
            ]);

        } catch (\Exception $e) {
            Log::error('API key verification error', [
                'error' => $e->getMessage(),
                'public_key' => $request->public_key
            ]);

            return response()->json([
                'valid' => false,
                'error' => 'Verification error',
                'code' => 'VERIFICATION_ERROR',
                'status' => 500
            ], 500);
        }
    }

    private function checkActionPermission(array $permissions, string $action): bool
    {
        $parts = explode('.', $action);
        if (count($parts) !== 2) {
            return false;
        }

        [$resource, $operation] = $parts;
        return isset($permissions[$resource][$operation]) && $permissions[$resource][$operation] === true;
    }

   
 
    private function getRemainingRateLimit(ApiKeys $apiKey): int
    {
        // Implémentation simple - à adapter selon vos besoins
        $dailyLimit = 1000; // Par exemple
        $usedToday = DB::table('api_key_usage_logs')
            ->where('public_key_id', $apiKey->public_key_id)
            ->whereDate('created_at', today())
            ->count();

        return max(0, $dailyLimit - $usedToday);
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
                'max_amount_per_transaction' => 100000,
                'max_amount_per_day' => 1000000,
                'allowed_currencies' => ['XAF', 'EUR', 'USD']
            ]
        ];
    }
}
