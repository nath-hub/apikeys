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
     * Affiche les logs d'utilisation avec pagination et filtres
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
            match($request->period) {
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
                'user_id', 'action', 'environment', 
                'status', 'suspicious_only', 'country_code', 
                'date_from', 'date_to', 'period'
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
     * Stocke un nouveau log d'utilisation
     */
    public function store(ApiKeyUsageLogRequest $request)
    {
        // $log = new ApiKeyUsageLogService();

        // $result = $log->logUsage($request);

        $result = ApiKeyUsageLog::create($request->all());
 
        return response()->json([
            'message' => 'Usage log created successfully',
            'data' => $result->load(['apiKey', 'user'])
        ], 201);
    }

    /**
     * Affiche un log spécifique
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
        $dateRange = match($period) {
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
