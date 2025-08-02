<?php

namespace App\Http\Services;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Support\Facades\Log;
use Exception;

class UserService
{

    private $httpClient;
    private $userServiceUrl;

    public function __construct()
    {
        $this->httpClient = new Client();
        $this->userServiceUrl = env('USER_SERVICE_URL', 'http://127.0.0.1:8001');
    }
    public function getUser()
    { 
        $token = request()->bearerToken();

        try {
            $response = $this->httpClient->post($this->userServiceUrl . '/api/auth/validate', [
                'headers' => [
                    'Authorization' => 'Bearer ' . $token,
                    'Content-Type' => 'application/json',
                ],
                'timeout' => 5,
            ]);

            $data = json_decode($response->getBody()->getContents(), true);

            if (isset($data['user_id'])) {
                //get entreprise de l'utilisateur
            }

            return $data['user_id'] ?? null;

        } catch (RequestException $e) {
            Log::error('Erreur validation token: ' . $e->getMessage());
            throw new Exception('Token invalide');
        }
    }


    function getUserCompany()
    { 
        try {
            $response = $this->httpClient->get($this->userServiceUrl . '/api/entreprises/me/company', [
                'headers' => [
                    'Authorization' => 'Bearer ' . request()->bearerToken(),
                    'Content-Type' => 'application/json',
                ],
                'timeout' => 5,
            ]);

            return json_decode($response->getBody()->getContents(), true);
        } catch (RequestException $e) {
            Log::error('Erreur récupération entreprise: ' . $e->getMessage());
            throw new Exception('Erreur récupération entreprise');
        }
    }
}
