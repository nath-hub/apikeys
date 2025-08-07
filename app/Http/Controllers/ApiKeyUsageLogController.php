<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Http\Services\ApiKeyUsageLogService;
use Illuminate\Http\Request;

use App\Models\ApiKeyUsageLog;
use App\Http\Requests\ApiKeyUsageLogRequest;
use Illuminate\Http\JsonResponse;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;

class ApiKeyUsageLogController extends Controller
{
    /**
     * @OA\Get(
     *     path="/apikeys/api-usage-logs",
     *     tags={"API Usage Logs"},
     *     summary="Lister les journaux d'utilisation API",
     *     description="Retourne une liste paginée des logs API",
     *     @OA\Parameter(
     *         name="page",
     *         in="query",
     *         description="Page de pagination",
     *         required=false,
     *         @OA\Schema(type="integer", example=1)
     *     ),
     *     @OA\Parameter(
     *         name="per_page",
     *         in="query",
     *         description="Nombre d’éléments par page",
     *         required=false,
     *         @OA\Schema(type="integer", example=15)
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Liste des journaux",
     *         @OA\JsonContent(
     *             @OA\Property(property="data", type="array", @OA\Items(type="object")),
     *             @OA\Property(property="meta", type="object"),
     *             @OA\Property(property="links", type="object")
     *         )
     *     ),
     *     @OA\Response(response=401, description="Non autorisé")
     * )
     */

    public function index(Request $request): JsonResponse
    {
        $query = ApiKeyUsageLog::with(['apiKey', 'user'])
            ->orderBy('created_at', 'desc');

        // Filtres
        if ($request->filled('user_id')) {
            $query->byUser($request->user_id);
        }

        // if ($request->filled('api_key_id')) {
        //     $query->byApiKey($request->api_key_id);
        // }

        if ($request->filled('action')) {
            $query->byAction($request->action);
        }

        if ($request->filled('environment')) {
            $query->byEnvironment($request->environment);
        }

        if ($request->filled('status')) {
            $query->byStatus($request->status);
        }

        if ($request->boolean('suspicious_only')) {
            $query->suspicious();
        }

        if ($request->filled('country_code')) {
            $query->byCountry($request->country_code);
        }

        // Filtres de date
        if ($request->filled('date_from')) {
            $query->where('created_at', '>=', Carbon::parse($request->date_from));
        }

        if ($request->filled('date_to')) {
            $query->where('created_at', '<=', Carbon::parse($request->date_to));
        }

        // Filtres prédéfinis
        if ($request->filled('period')) {
            match ($request->period) {
                'today' => $query->today(),
                'week' => $query->thisWeek(),
                'month' => $query->thisMonth(),
                default => null
            };
        }

        $perPage = min($request->get('per_page', 15), 100); // Max 100 par page
        $logs = $query->paginate($perPage);

        return response()->json([
            'data' => $logs->items(),
            'pagination' => [
                'current_page' => $logs->currentPage(),
                'per_page' => $logs->perPage(),
                'total' => $logs->total(),
                'last_page' => $logs->lastPage(),
                'from' => $logs->firstItem(),
                'to' => $logs->lastItem()
            ],
            'filters_applied' => $request->only([
                'user_id',
                'action',
                'environment',
                'status',
                'suspicious_only',
                'country_code',
                'date_from',
                'date_to',
                'period'
            ])
        ]);
    }

    /**
     * Affiche les logs d'un utilisateur spécifique
     */
    public function indexByUserId(int $userId, Request $request): JsonResponse
    {
        $query = ApiKeyUsageLog::byUser($userId)
            ->with(['apiKey'])
            ->orderBy('created_at', 'desc');

        // Filtres additionnels
        if ($request->filled('action')) {
            $query->byAction($request->action);
        }

        if ($request->filled('environment')) {
            $query->byEnvironment($request->environment);
        }

        if ($request->filled('days')) {
            $days = min($request->days, 90); // Max 90 jours
            $query->where('created_at', '>=', now()->subDays($days));
        }

        $perPage = min($request->get('per_page', 15), 50);
        $logs = $query->paginate($perPage);

        // Statistiques pour cet utilisateur
        $stats = $this->getUserStatistics($userId, $request->get('days', 30));

        return response()->json([
            'user_id' => $userId,
            'data' => $logs->items(),
            'pagination' => [
                'current_page' => $logs->currentPage(),
                'per_page' => $logs->perPage(),
                'total' => $logs->total(),
                'last_page' => $logs->lastPage()
            ],
            'statistics' => $stats
        ]);
    }

    /**
     * @OA\Post(
     *     path="/apikeys/api-usage-logs",
     *     tags={"API Usage Logs"},
     *     summary="Créer un journal d’utilisation d’API",
     *     description="Enregistre les détails d'une requête API pour analyse ou audit.",
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"public_key_id", "private_key_id", "http_method", "ip_address", "environment", "status"},
     *             @OA\Property(property="user_id", type="string", format="uuid", example="550e8400-e29b-41d4-a716-446655440000"),
     *             @OA\Property(property="public_key_id", type="string", maxLength=255, example="pk_live_1234"),
     *             @OA\Property(property="private_key_id", type="string", maxLength=255, example="sk_live_1234"),
     *             @OA\Property(property="action", type="string", maxLength=255, example="create_payment"),
     *             @OA\Property(property="endpoint", type="string", maxLength=500, example="/api/payments"),
     *             @OA\Property(property="http_method", type="string", enum={"GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD"}, example="POST"),
     *             @OA\Property(property="request_uuid", type="string", format="uuid", example="123e4567-e89b-12d3-a456-426614174000"),
     *             @OA\Property(property="request_id", type="string", maxLength=255, example="req_987654321"),
     *             @OA\Property(property="ip_address", type="string", format="ipv4", example="102.244.123.1"),
     *             @OA\Property(property="user_agent", type="string", maxLength=1000, example="PostmanRuntime/7.31.1"),
     *             @OA\Property(property="country_code", type="string", maxLength=5, example="CM"),
     *             @OA\Property(property="environment", type="string", enum={"test","live","sandbox"}, example="live"),
     *             @OA\Property(property="response_time_ms", type="integer", minimum=0, maximum=300000, example=240),
     *             @OA\Property(property="response_status_code", type="integer", minimum=100, maximum=599, example=200),
     *             @OA\Property(property="request_size_bytes", type="integer", minimum=0, example=512),
     *             @OA\Property(property="response_size_bytes", type="integer", minimum=0, example=2048),
     *             @OA\Property(property="signature_valid", type="boolean", example=true),
     *             @OA\Property(property="source_service", type="string", maxLength=100, example="payment_service"),
     *             @OA\Property(property="request_headers", type="object", example={"Authorization": "Bearer sk_live_xxx"}),
     *             @OA\Property(property="amount", type="number", format="float", minimum=0, maximum=999999999.99, example=10000.50),
     *             @OA\Property(property="currency", type="string", maxLength=3, example="XAF"),
     *             @OA\Property(property="status", type="string", enum={"success","failed","blocked","rate_limited"}, example="success"),
     *             @OA\Property(property="is_suspicious", type="boolean", example=false),
     *             @OA\Property(property="error_message", type="string", maxLength=1000, example="Invalid signature"),
     *             @OA\Property(property="error_code", type="string", maxLength=100, example="401"),
     *             @OA\Property(property="city", type="string", maxLength=100, example="Yaoundé"),
     *             @OA\Property(property="region", type="string", maxLength=100, example="Centre"),
     *             @OA\Property(property="latitude", type="number", format="float", minimum=-90, maximum=90, example=3.848),
     *             @OA\Property(property="longitude", type="number", format="float", minimum=-180, maximum=180, example=11.5021)
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Créé avec succès",
     *         @OA\JsonContent(
     *             @OA\Property(property="success", type="boolean", example=true),
     *             @OA\Property(property="message", type="string", example="Journal enregistré avec succès"),
     *             @OA\Property(property="data", type="object")
     *         )
     *     ),
     *     @OA\Response(response=400, description="Requête invalide"),
     *     @OA\Response(response=401, description="Non autorisé"),
     *     @OA\Response(response=422, description="Erreur de validation"),
     *     @OA\Response(response=500, description="Erreur interne du serveur")
     * )
     */

    public function store(ApiKeyUsageLogRequest $request)
    {

        $result = ApiKeyUsageLog::create($request->all());

        return response()->json([
            'message' => 'Usage log created successfully',
            'data' => $result->load(['apiKey', 'user'])
        ], 201);
    }

    /**
     * @OA\Get(
     *     path="/apikeys/api-usage-logs/{log}",
     *     tags={"API Usage Logs"},
     *     summary="Afficher un journal d’usage",
     *     @OA\Parameter(
     *         name="log",
     *         in="path",
     *         description="ID du log",
     *         required=true,
     *         @OA\Schema(type="string", format="uuid", example="f4d6eb57-45f8-4b89-9d12-cae4c56877f4")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Détails du journal",
     *         @OA\JsonContent(type="object")
     *     ),
     *     @OA\Response(response=404, description="Non trouvé")
     * )
     */

    public function show(ApiKeyUsageLog $log): JsonResponse
    {
        return response()->json([
            'data' => $log->load(['apiKey', 'user'])
        ]);
    }

    /**
     * Statistiques d'utilisation
     */
    public function statistics(Request $request): JsonResponse
    {
        $period = $request->get('period', 'month'); // day, week, month, year
        $environment = $request->get('environment');

        $stats = $this->getGlobalStatistics($period, $environment);

        return response()->json([
            'period' => $period,
            'environment' => $environment,
            'statistics' => $stats
        ]);
    }

    /**
     * Logs d'activité suspecte
     */
    public function suspicious(Request $request): JsonResponse
    {
        $query = ApiKeyUsageLog::suspicious()
            ->with(['apiKey', 'user'])
            ->orderBy('created_at', 'desc');

        if ($request->filled('days')) {
            $days = min($request->days, 30);
            $query->where('created_at', '>=', now()->subDays($days));
        }

        $logs = $query->paginate(20);

        return response()->json([
            'message' => 'Suspicious activity logs',
            'data' => $logs->items(),
            'pagination' => [
                'current_page' => $logs->currentPage(),
                'total' => $logs->total(),
                'last_page' => $logs->lastPage()
            ]
        ]);
    }

    /**
     * Analyse des performances
     */
    public function performance(Request $request): JsonResponse
    {
        $days = min($request->get('days', 7), 30);

        $performance = ApiKeyUsageLog::select(
            DB::raw('DATE(created_at) as date'),
            DB::raw('AVG(response_time_ms) as avg_response_time'),
            DB::raw('MAX(response_time_ms) as max_response_time'),
            DB::raw('COUNT(*) as total_requests'),
            DB::raw('SUM(CASE WHEN status = "success" THEN 1 ELSE 0 END) as successful_requests')
        )
            ->where('created_at', '>=', now()->subDays($days))
            ->whereNotNull('response_time_ms')
            ->groupBy(DB::raw('DATE(created_at)'))
            ->orderBy('date', 'desc')
            ->get();

        return response()->json([
            'period_days' => $days,
            'performance_data' => $performance
        ]);
    }


    /**
     * Obtient les statistiques d'un utilisateur
     */
    private function getUserStatistics(int $userId, int $days): array
    {
        $baseQuery = ApiKeyUsageLog::byUser($userId)
            ->where('created_at', '>=', now()->subDays($days));

        return [
            'total_requests' => $baseQuery->count(),
            'successful_requests' => $baseQuery->successful()->count(),
            'failed_requests' => $baseQuery->failed()->count(),
            'suspicious_requests' => $baseQuery->suspicious()->count(),
            'unique_ips' => $baseQuery->distinct('ip_address')->count('ip_address'),
            'countries_used' => $baseQuery->distinct('country_code')->whereNotNull('country_code')->count('country_code'),
            'avg_response_time_ms' => round($baseQuery->whereNotNull('response_time_ms')->avg('response_time_ms')),
            'actions_breakdown' => $baseQuery->select('action', DB::raw('COUNT(*) as count'))
                ->groupBy('action')
                ->orderBy('count', 'desc')
                ->pluck('count', 'action')
                ->toArray(),
            'environments_breakdown' => $baseQuery->select('environment', DB::raw('COUNT(*) as count'))
                ->groupBy('environment')
                ->pluck('count', 'environment')
                ->toArray(),
            'daily_usage' => $baseQuery->select(
                DB::raw('DATE(created_at) as date'),
                DB::raw('COUNT(*) as requests')
            )
                ->groupBy(DB::raw('DATE(created_at)'))
                ->orderBy('date', 'desc')
                ->limit(30)
                ->pluck('requests', 'date')
                ->toArray()
        ];
    }

    /**
     * Obtient les statistiques globales
     */
    private function getGlobalStatistics(string $period, ?string $environment): array
    {
        $dateRange = match ($period) {
            'day' => [now()->startOfDay(), now()->endOfDay()],
            'week' => [now()->startOfWeek(), now()->endOfWeek()],
            'month' => [now()->startOfMonth(), now()->endOfMonth()],
            'year' => [now()->startOfYear(), now()->endOfYear()],
            default => [now()->startOfMonth(), now()->endOfMonth()]
        };

        $baseQuery = ApiKeyUsageLog::whereBetween('created_at', $dateRange);

        if ($environment) {
            $baseQuery->byEnvironment($environment);
        }

        // Statistiques de base
        $basicStats = [
            'total_requests' => $baseQuery->count(),
            'successful_requests' => $baseQuery->successful()->count(),
            'failed_requests' => $baseQuery->failed()->count(),
            'blocked_requests' => $baseQuery->byStatus('blocked')->count(),
            'rate_limited_requests' => $baseQuery->byStatus('rate_limited')->count(),
            'suspicious_requests' => $baseQuery->suspicious()->count(),
            'unique_users' => $baseQuery->distinct('user_id')->count('user_id'),
            'unique_ips' => $baseQuery->distinct('ip_address')->count('ip_address'),
            'unique_countries' => $baseQuery->distinct('country_code')->whereNotNull('country_code')->count('country_code')
        ];

        // Top des actions
        $topActions = $baseQuery->select('action', DB::raw('COUNT(*) as count'))
            ->whereNotNull('action')
            ->groupBy('action')
            // ->orderBy('COUNT(*) DESC')
            ->limit(10)
            ->pluck('count', 'action')
            ->toArray();

        // Top des pays
        $topCountries = $baseQuery->select('country_code', DB::raw('COUNT(*) as count'))
            ->whereNotNull('country_code')
            ->groupBy('country_code')
            // ->orderBy('COUNT(*) DESC')
            ->limit(10)
            ->pluck('count', 'country_code')
            ->toArray();

        // Statistiques de performance
        $performanceStats = [
            'avg_response_time_ms' => round($baseQuery->whereNotNull('response_time_ms')->avg('response_time_ms')),
            'max_response_time_ms' => $baseQuery->max('response_time_ms'),
            'slow_requests_count' => $baseQuery->slowRequests(5000)->count(), // > 5 secondes
            'avg_request_size_bytes' => round($baseQuery->whereNotNull('request_size_bytes')->avg('request_size_bytes')),
            'avg_response_size_bytes' => round($baseQuery->whereNotNull('response_size_bytes')->avg('response_size_bytes'))
        ];

        // Répartition par environnement
        $environmentBreakdown = $baseQuery->select('environment', DB::raw('COUNT(*) as count'))
            ->groupBy('environment')
            ->pluck('count', 'environment')
            ->toArray();

        // Timeline des requêtes (par heure pour le jour, par jour pour les autres)
        $timelineFormat = $period === 'day' ? 'Y-m-d H:00:00' : 'Y-m-d';
        $timeline = $baseQuery->select(
            DB::raw("DATE_FORMAT(created_at, '" . ($period === 'day' ? '%Y-%m-%d %H:00:00' : '%Y-%m-%d') . "') as time_period"),
            DB::raw('COUNT(*) as requests'),
            DB::raw('SUM(CASE WHEN status = "success" THEN 1 ELSE 0 END) as successful'),
            DB::raw('SUM(CASE WHEN status = "failed" THEN 1 ELSE 0 END) as failed')
        )
            ->groupBy('time_period')
            ->orderBy('time_period')
            ->get()
            ->toArray();

        return [
            'basic' => $basicStats,
            'performance' => $performanceStats,
            'top_actions' => $topActions,
            'top_countries' => $topCountries,
            'environment_breakdown' => $environmentBreakdown,
            'timeline' => $timeline,
            'date_range' => [
                'from' => $dateRange[0]->toISOString(),
                'to' => $dateRange[1]->toISOString()
            ]
        ];
    }
}
