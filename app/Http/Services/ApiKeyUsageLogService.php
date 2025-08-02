<?php 

namespace App\Http\Services;

use App\Models\ApiKeyUsageLog;
use App\Models\ApiKey;
use App\Models\ApiKeys;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class ApiKeyUsageLogService{
    // private $geoipService;
    // private $suspiciousActivityDetector;

    public function __construct()
    {
        // $this->geoipService = app(GeoIpService::class);
        // $this->suspiciousActivityDetector = app(SuspiciousActivityDetector::class);
    }


     /**
     * Log complet d'utilisation d'API key
     */
    public function logUsage( Request $request): ApiKeyUsageLog 
    {
        $startTime = microtime(true);

        // Collecter les données géographiques
        $geoData = $this->getGeoLocation($request->ip());
        
        // Analyser les headers (en filtrant les données sensibles)
        $safeHeaders = $this->filterSensitiveHeaders($request->headers->all());
        
        // Détecter l'activité suspecte
        $isSuspicious = $this->detectSuspiciousActivity($request->key_id, $request, $geoData);
        
        // Extraire les informations financières si disponibles
        $financialData = $this->extractFinancialData($request);

        $logData = [
            // 'api_key_id' => $request->api_key_id,
            'user_id' => $request->user_id,
            'public_key_id' => $request->header('X-API-Public-Key') ?? $request->public_key_id,
            'private_key_id' => $request->header('X-API-Private-Key') ?? $request->private_key_id,
            'action' => $request->input('action') ?? $request->route()?->getActionMethod(),
            'endpoint' => $request->getPathInfo(),
            'http_method' => $request->getMethod(),
            'request_uuid' => $request->header('X-API-UUID') ?? $request->input('uuid'),
            'request_id' => $request->header('X-Request-ID') ?? uniqid('req_'),
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'environment' => $request->header('X-API-Environment') ?? $request->input('environment'),
            'response_time_ms' => $responseTime ?? round((microtime(true) - $startTime) * 1000),
            'response_status_code' => $request->response_status_code,
            'request_size_bytes' => strlen($request->getContent()),
            'response_size_bytes' => $request->responseData ? strlen(json_encode($request->responseData)) : null,
            'signature_valid' => $request->get('signature_valid', true),
            'source_service' => $request->header('X-Source-Service'),
            'request_headers' => $safeHeaders,
            'status' => $this->determineStatus($request->response_status_code),
            'is_suspicious' => $isSuspicious,
            'created_at' => now(),
            
            // Données géographiques
            'country_code' => $geoData['country_code'] ?? null,
            'city' => $geoData['city'] ?? null,
            'region' => $geoData['region'] ?? null,
            'latitude' => $geoData['latitude'] ?? null,
            'longitude' => $geoData['longitude'] ?? null,
            
            // Données financières
            'amount' => $financialData['amount'] ?? null,
            'currency' => $financialData['currency'] ?? null,
            
            // Données d'erreur
            'error_message' => $responseData['error'] ?? null,
            'error_code' => $responseData['code'] ?? null,
        ];

        $log = ApiKeyUsageLog::create($logData);

        // Actions post-création
        // $this->postLogActions($log, $request);

        return $log;
    }

    /**
     * Obtient les données de géolocalisation pour une IP
     */
    private function getGeoLocation(string $ip): array
    {
        if ($ip === '127.0.0.1' || $ip === '::1') {
            return ['country_code' => 'LOCAL'];
        }

        $cacheKey = "geoip:{$ip}";
        
        return Cache::remember($cacheKey, 3600, function() use ($ip) {
            try {
                // Utiliser un service de géolocalisation (exemple avec ipapi.co)
                $response = Http::timeout(3)->get("http://ipapi.co/{$ip}/json/");
                
                if ($response->successful()) {
                    $data = $response->json();
                    return [
                        'country_code' => $data['country_code'] ?? null,
                        'city' => $data['city'] ?? null,
                        'region' => $data['region'] ?? null,
                        'latitude' => $data['latitude'] ?? null,
                        'longitude' => $data['longitude'] ?? null,
                    ];
                }
            } catch (\Exception $e) {
                Log::warning('GeoIP lookup failed', ['ip' => $ip, 'error' => $e->getMessage()]);
            }

            return [];
        });
    }

    /**
     * Filtre les headers sensibles
     */
    private function filterSensitiveHeaders(array $headers): array
    {
        $sensitiveKeys = [
            'x-api-private-key',
            'x-api-signature', 
            'authorization',
            'cookie',
            'x-forwarded-for'
        ];

        return array_filter($headers, function($key) use ($sensitiveKeys) {
            return !in_array(strtolower($key), $sensitiveKeys);
        }, ARRAY_FILTER_USE_KEY);
    }

    /**
     * Détecte les activités suspectes
     */
    private function detectSuspiciousActivity($apiKey, Request $request, array $geoData)
    {
        $suspiciousIndicators = [];
         
        // 1. Changement géographique rapide
        $lastLog = ApiKeyUsageLog::where('public_key_id', $request->public_key_id)
            ->where('created_at', '>', now()->subMinutes(30))
            ->orderBy('created_at', 'desc')
            ->first();

        if ($lastLog && $lastLog->country_code && $geoData['country_code']) {
            if ($lastLog->country_code !== $geoData['country_code']) {
                $suspiciousIndicators[] = 'geographic_anomaly';
            }
        }

        // 2. Fréquence d'utilisation anormale
        $recentCount = ApiKeyUsageLog::where('public_key_id', $request->public_key_id)
            ->where('created_at', '>', now()->subMinutes(5))
            ->count();

        if ($recentCount > 100) { // Plus de 100 requêtes en 5 minutes
            $suspiciousIndicators[] = 'high_frequency';
        }

        // 3. User-Agent suspect
        $userAgent = $request->userAgent();
        if (!$userAgent || strlen($userAgent) < 10) {
            $suspiciousIndicators[] = 'suspicious_user_agent';
        }

        // 4. Horaires inhabituels (exemple: 2h-6h du matin)
        $hour = now()->hour;
        if ($hour >= 2 && $hour <= 6) {
            $normalUsage = ApiKeyUsageLog::where('public_key_id', $request->public_key_id)
                ->whereTime('created_at', '>=', '02:00:00')
                ->whereTime('created_at', '<=', '06:00:00')
                ->where('created_at', '>', now()->subDays(30))
                ->count();
                
            if ($normalUsage < 5) { // Moins de 5 utilisations nocturnes dans les 30 derniers jours
                $suspiciousIndicators[] = 'unusual_time';
            }
        }

        return count($suspiciousIndicators) >= 2; // Suspect si 2+ indicateurs
    }

    /**
     * Extrait les données financières de la requête
     */
    private function extractFinancialData(Request $request): array
    {
        return [
            'amount' => $request->input('amount'),
            'currency' => $request->input('currency')
        ];
    }

    /**
     * Détermine le statut basé sur le code de réponse
     */
    private function determineStatus(int $statusCode): string
    {
        if ($statusCode >= 200 && $statusCode < 300) {
            return 'success';
        } elseif ($statusCode === 429) {
            return 'rate_limited';
        } elseif ($statusCode === 403) {
            return 'blocked';
        } else {
            return 'failed';
        }
    }

    /**
     * Actions à effectuer après la création du log
     */
    private function postLogActions(ApiKeyUsageLog $log, ApiKeys $apiKey): void
    {
        // Alertes en temps réel pour activité suspecte
        if ($log->is_suspicious) {
            // Notification à l'équipe de sécurité
            Log::warning('Suspicious API key activity detected', [
                'public_key_id' => $apiKey->public_key_id,
                'user_id' => $apiKey->user_id,
                'ip_address' => $log->ip_address,
                'log_id' => $log->id
            ]);

            // Possibilité d'envoyer une notification push/email
            // event(new SuspiciousActivityDetected($log));
        }

        // Mise à jour des statistiques en cache
        $this->updateUsageStatistics($apiKey, $log);
    }

    /**
     * Met à jour les statistiques d'usage en cache
     */
    private function updateUsageStatistics(ApiKeys $apiKey, ApiKeyUsageLog $log): void
    {
        $cacheKey = "api_key_stats:{$apiKey->id}:" . now()->format('Y-m-d');
        
        Cache::increment($cacheKey . ':total_requests');
        
        if ($log->status === 'success') {
            Cache::increment($cacheKey . ':successful_requests');
        } else {
            Cache::increment($cacheKey . ':failed_requests');
        }

        if ($log->response_time_ms) {
            // Moyenne mobile simple du temps de réponse
            $avgKey = $cacheKey . ':avg_response_time';
            $currentAvg = Cache::get($avgKey, 0);
            $newAvg = ($currentAvg + $log->response_time_ms) / 2;
            Cache::put($avgKey, $newAvg, now()->addDays(7));
        }
    }
}