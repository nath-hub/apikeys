<?php

namespace App\Helpers;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Support\Facades\Log;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class InternalHttpClient
{
    private Client $httpClient;
    private ?string $bearerToken;
    private int $timeout;
    private int $retries;
    private ?string $apiKeyId = null;
    private ?string $userId = null;
    private ?string $publicKeyId = null;
    private ?string $privateKeyId = null;
    private ?string $environment = null;
    private ?string $requestUuid = null;
    private ?string $ipAddress = null;
    private ?array $permissions = null;

    public function __construct(?string $bearerToken = null, int $timeout = 30, int $retries = 1)
    {
        $this->httpClient = new Client([
            'timeout' => $timeout,
            'connect_timeout' => 5,
            'verify' => false, // À ajuster selon votre environnement
        ]);

        $this->bearerToken = $bearerToken;
        $this->timeout = $timeout;
        $this->retries = $retries;

        $this->apiKeyId = null;
        $this->userId = null;
        $this->publicKeyId = null;
        $this->privateKeyId = null;
        $this->environment = null;
        $this->requestUuid = null;
        $this->ipAddress = null;
        $this->permissions = null;
    }


    /**
     * Requête GET
     */
    public function get(Request $request, string $serviceUrl, string $endpoint, array $permissions = []): array
    {
        return $this->call($request, $serviceUrl, $endpoint, [], 'GET', $permissions);
    }

    /**
     * Requête POST
     */
    public function post($request, string $serviceUrl, string $endpoint, array $data = [], array $permissions = []): array
    {
        return $this->call($request, $serviceUrl, $endpoint, $data, 'POST', $permissions);
    }

    /**
     * Requête PUT
     */
    public function put(Request $request, string $serviceUrl, string $endpoint, array $data = [], array $permissions = []): array
    {
        return $this->call($request, $serviceUrl, $endpoint, $data, 'PUT', $permissions);
    }

    /**
     * Requête PATCH
     */
    public function patch(Request $request, string $serviceUrl, string $endpoint, array $data = [], array $permissions = []): array
    {
        return $this->call($request, $serviceUrl, $endpoint, $data, 'PATCH', $permissions);
    }

    /**
     * Requête DELETE
     */
    public function delete(Request $request, string $serviceUrl, string $endpoint, array $permissions = []): array
    {
        return $this->call($request, $serviceUrl, $endpoint, [], 'DELETE', $permissions);
    }

    public function logUsage(Request $request, string $httpMethod, string $endpoint, int $statusCode, $responseData, int $responseTime, $responseBody, $safeHeaders, $user_agent, $request_id)
    {
        $startTime = microtime(true);

        // Collecter les données géographiques
        $geoData = $this->getGeoLocation($request->ip());

        // Extraire les informations financières si disponibles
        $financialData = $this->extractFinancialData($request);

        $logData = [
            'user_id' => $request->user_id,
            'public_key_id' => $request->header('X-API-Public-Key') ?? $request->public_key_id,
            'private_key_id' => $request->header('X-API-Private-Key') ?? $request->private_key_id,
            'action' => $request->input('action') ?? $request->route()?->getActionMethod(),
            'endpoint' => $endpoint,
            'http_method' => $httpMethod,
            'request_uuid' => $request->header('X-API-UUID') ?? $request->input('uuid'),
            'request_id' => $request_id,
            'ip_address' => $request->ip(),
            'user_agent' => $user_agent,
            'environment' => $request->header('X-API-Environment') ?? $request->input('environment'),
            'response_time_ms' => $responseTime ?? round((microtime(true) - $startTime) * 1000),
            'response_status_code' => $statusCode,
            'request_size_bytes' => strlen($responseBody),
            'response_size_bytes' => $responseData ? strlen(json_encode($responseData)) : null,
            'signature_valid' => $request->get('signature_valid', true),
            'source_service' => $request->header('X-Source-Service'),
            'request_headers' => $safeHeaders,
            'status' => $this->determineStatus($statusCode),
            'is_suspicious' => false,
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

        $result = $this->sendLogToService($logData);

        return $result;
    }

    private function getGeoLocation(string $ip): array
    {
        if ($ip === '127.0.0.1' || $ip === '::1') {
            return ['country_code' => 'LOCAL'];
        }

        $cacheKey = "geoip:{$ip}";

        return Cache::remember($cacheKey, 3600, function () use ($ip) {
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

        return array_filter($headers, function ($key) use ($sensitiveKeys) {
            return !in_array(strtolower($key), $sensitiveKeys);
        }, ARRAY_FILTER_USE_KEY);
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
     * Envoyer le log au service de logs
     */
    private function sendLogToService(array $logData)
    {
        try {
            $logClient = new Client([
                'timeout' => 10,
                'connect_timeout' => 5,
                'verify' => false,
            ]);

            $apikeysServiceUrl = config('services.services_apikeys.url', 'http://apikeys-service');
            $logEndpoint = rtrim($apikeysServiceUrl, '/') . '/api/apikeys/api-usage-logs';

            // Headers pour la requête de log
            $logHeaders = [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'X-Request-ID' => $this->generateRequestId(),
                'X-Service-Name' => config('app.name', 'unknown'),
            ];

            // Ajouter le Bearer token si disponible
            if ($this->bearerToken) {
                $logHeaders['Authorization'] = 'Bearer ' . $this->bearerToken;
            }

            $response = $logClient->post($logEndpoint, [
                'headers' => $logHeaders,
                'json' => $logData,
                'timeout' => 10,
            ]);


            $body = (string) $response->getBody();

            // Convertir en tableau associatif (true)
            $decoded = json_decode($body, true);

            // Loguer proprement
            Log::debug('API usage log sent successfully', [
                'status_code' => $response->getStatusCode(),
                'log_endpoint' => $logEndpoint,
                'response' => $decoded
            ]);


            return $response;

        } catch (Exception $e) {
            Log::error('Failed to send log to service', [
                'error' => $e->getMessage(),
                // 'log_data' => $logData
            ]);

            return $e;
        }
    }



    /**
     * Méthode mise à jour pour passer les headers à logApiUsage
     */
    private function call(Request $request, string $serviceUrl, string $endpoint, array $data = [], string $method = 'GET', array $permissions = [])
    {
        $startTime = microtime(true);
        $url = rtrim($serviceUrl, '/') . '/' . ltrim($endpoint, '/');

        $headers = $this->buildHeaders($permissions);
        $options = [
            'headers' => $headers,
            'timeout' => $this->timeout,
        ];

        // Ajouter les données selon la méthode
        if (in_array(strtoupper($method), ['POST', 'PUT', 'PATCH']) && !empty($data)) {
            $options['json'] = $data;
        } elseif (strtoupper($method) === 'GET' && !empty($data)) {
            $options['query'] = $data;
        }

        $attempt = 0;
        $lastException = null;
        $response = null;

        $safeHeaders = $this->filterSensitiveHeaders($request->headers->all());
        $request_id = $request->header('X-Request-ID') ?? uniqid('req_');
        $user_agent = $request->userAgent();


        while ($attempt < $this->retries) {
            try {
                $response = $this->httpClient->request($method, $url, $options);

                $statusCode = $response->getStatusCode();
                $responseBody = $response->getBody()->getContents();
                $responseTime = round((microtime(true) - $startTime) * 1000);


                Log::info("Microservice request successful", [
                    'method' => $method,
                    'url' => $url,
                    'status_code' => $statusCode,
                    'attempt' => $attempt + 1
                ]);

                $result = [
                    'success' => true,
                    'status_code' => $statusCode,
                    'data' => json_decode($responseBody, true) ?? $responseBody,
                    'headers' => $response->getHeaders()
                ];

                // Enregistrer le log de la requête avec les headers
                $this->logUsage($request, $method, $endpoint, $statusCode, $result['data'], $responseTime, $responseBody, $safeHeaders, $user_agent, $request_id);

                return $result;

            } catch (RequestException $e) {
                $lastException = $e;
                $attempt++;

                $statusCode = $e->getResponse() ? $e->getResponse()->getStatusCode() : 0;
                $responseBody = $e->getResponse() ? $e->getResponse()->getBody()->getContents() : '';

                Log::warning("Microservice request failed", [
                    'method' => $method,
                    'url' => $url,
                    'status_code' => $statusCode,
                    'attempt' => $attempt,
                    'error' => $e->getMessage(),
                    'response_body' => $responseBody
                ]);

                // Ne pas réessayer pour certains codes d'erreur
                if (in_array($statusCode, [400, 401, 403, 404, 422])) {
                    break;
                }

                // Attendre avant de réessayer
                if ($attempt < $this->retries) {
                    sleep(pow(2, $attempt)); // Backoff exponentiel
                }

            } catch (GuzzleException $e) {
                $lastException = $e;
                $attempt++;

                Log::error("Microservice request exception", [
                    'method' => $method,
                    'url' => $url,
                    'attempt' => $attempt,
                    'error' => $e->getMessage()
                ]);

                if ($attempt < $this->retries) {
                    sleep(pow(2, $attempt));
                }
            }
        }

        // Calculer le temps de réponse total
        $responseTime = round((microtime(true) - $startTime) * 1000);

        // Retourner l'erreur après tous les essais
        $result = $this->handleError($lastException);

        // Enregistrer le log de la requête échouée avec les headers
        $this->logUsage($request, $method, $endpoint, $result['status_code'], $result['data'], $responseTime, $responseBody, $safeHeaders, $user_agent, $request_id);

        return $result;
    }

    /**
     * Construire les headers de la requête
     */
    private function buildHeaders(array $permissions = []): array
    {
        $headers = [
            'Accept' => 'application/json',
            'Content-Type' => 'application/json',
            'X-Request-ID' => $this->generateRequestId(),
            'X-Service-Name' => config('app.name', 'unknown'),
        ];

        // Ajouter le Bearer token si disponible
        if ($this->bearerToken) {
            $headers['Authorization'] = 'Bearer ' . $this->bearerToken;
        }

        // Ajouter les permissions personnalisées
        if (!empty($permissions)) {
            $headers['X-Permissions'] = json_encode($permissions);
        }

        return $headers;
    }

    /**
     * Générer un ID unique pour la requête
     */
    private function generateRequestId(): string
    {
        return uniqid('req_', true);
    }

    /**
     * Gérer les erreurs
     */
    private function handleError(?Exception $exception): array
    {
        if ($exception instanceof RequestException && $exception->getResponse()) {
            $statusCode = $exception->getResponse()->getStatusCode();
            $responseBody = $exception->getResponse()->getBody()->getContents();

            return [
                'success' => false,
                'status_code' => $statusCode,
                'error' => $exception->getMessage(),
                'data' => json_decode($responseBody, true) ?? $responseBody,
            ];
        }

        return [
            'success' => false,
            'status_code' => 500,
            'error' => $exception ? $exception->getMessage() : 'Unknown error occurred',
            'data' => null,
        ];
    }

}