<?php

namespace App\Http\Services;

use App\Helpers\InternalHttpClient;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Illuminate\Support\Facades\Log;
use Exception;
use Illuminate\Http\Request;

class UserService
{
 
    private InternalHttpClient $httpClient;  

    public function __construct()
    {
        
        $bearerToken = request()->bearerToken();
        $this->httpClient = new InternalHttpClient($bearerToken);
    }
    public function getUser(Request $request)
    {
        $token = request()->bearerToken();

        try {

             $orderServiceUrl = config('services.services_user.url');

            $response = $this->httpClient->get(
                $request,
                $orderServiceUrl,
                '/api/auth/validate',
                ['create:orders']
            );

            if ($response['success']) {
                Log::info($response['data']);
                return $response['data']['user_id'];
            }

            return [
                'valid' => false,
                'error' => 'Failed to create order',
                'error_code' => 'API_VERIFICATION_FAILED',
                'details' => $response['error'],
                'status_code' => $response['status_code']
            ];

            

        } catch (RequestException $e) {
            Log::error('Erreur validation token: ' . $e->getMessage());
            throw new Exception('Token invalide');
        }
    }


    function getUserCompany(Request $request)
    {
        try {
            $orderServiceUrl = config('services.services_user.url');

            $response = $this->httpClient->get(
                $request,
                $orderServiceUrl,
                '/api/entreprises/me/company',
                ['create:orders']
            );

            if ($response['success']) {
                Log::info($response['data']);
                return $response['data'];
            }

            return [
                'valid' => false,
                'error' => 'Failed to create order',
                'error_code' => 'API_VERIFICATION_FAILED',
                'details' => $response['error'],
                'status_code' => $response['status_code']
            ];

            // return json_decode($response->getBody()->getContents(), true);
        } catch (RequestException $e) {
            Log::error('Erreur récupération entreprise: ' . $e->getMessage());
            throw new Exception('Erreur récupération entreprise');
        }
    }
}
