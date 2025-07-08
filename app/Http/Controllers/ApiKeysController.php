<?php

namespace App\Http\Controllers;

use App\Models\ApiKeys;
use App\Http\Controllers\Controller; 
use App\Http\Services\ApiKeyService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * @OA\Tag(
 *     name="API Keys",
 *     description="Gestion des clés API pour l'authentification"
 * )
 */
class ApiKeysController extends Controller
{

    public function __construct(private ApiKeyService $apiKeyService) {}


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
        $query = ApiKeys::where('user_id', $request->user()->id)
            ->with(['creator', 'revoker']);

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
                'masked_key' => $this->maskApiKey($key->key_type, $key->environment),
                'permissions' => $key->permissions,
                'ip_whitelist' => $key->ip_whitelist,
            ];
        });

        return response()->json([
            'message' => 'Clés API récupérées',
            'data' => $data
        ]);
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
     *                 @OA\Property(property="public_key", type="string", example="pk_test_abcd1234efgh5678ijkl9012mnop3456"),
     *                 @OA\Property(property="private_key", type="string", example="sk_test_abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yzab5678cdef9012"),
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
            'name' => 'nullable|string|max:100',
            'description' => 'nullable|string|max:500',
            'environment' => 'required|in:test,live,sandbox',
            'permissions' => 'nullable|array',
            'ip_whitelist' => 'nullable|array',
            'ip_whitelist.*' => 'ip',
        ]);

        $user = $request->user();
        $company = $user->company; // Assuming relationship exists

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
    public function destroy(Request $request, string $keyId): JsonResponse
    {
        $apiKey = ApiKeys::where('key_id', $keyId)
            ->where('user_id', $request->user()->id)
            ->first();

        if (!$apiKey) {
            return response()->json(['message' => 'Clé API non trouvée'], 404);
        }

        $success = $this->apiKeyService->revokeKey(
            $keyId,
            $request->user(),
            $request->input('reason')
        );

        if (!$success) {
            return response()->json(['message' => 'Impossible de révoquer la clé'], 400);
        }

        return response()->json(['message' => 'Clé API révoquée avec succès']);
    }

    private function maskApiKey(string $keyType, string $environment): string
    {
        return "{$keyType}_{$environment}_****...****" . substr(str_repeat('*', 8), 0, 4);
    }
}
