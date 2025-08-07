<?php

use App\Http\Controllers\ApiKeysController;
use App\Http\Controllers\ApiKeyUsageLogController;
use App\Http\Services\ApiKeyService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::prefix('apikeys/')->middleware('auth:sanctum')->group(function () {

    Route::get('', [ApiKeysController::class, 'index'])->name('api.index');
    Route::post('generate', [ApiKeysController::class, 'store'])->name('api.store');
    Route::post('verify_keys', [ApiKeysController::class, 'verifyKeys'])->name('api.verifyKeys');
    Route::put('update', [ApiKeysController::class, 'updateKey'])->name('api.update');
    Route::delete('{id}/delete', [ApiKeysController::class, 'destroy'])->name('api.destroy');
});
 

Route::prefix('apikeys/')->group(function () {
    // Logs d'utilisation
    Route::get('/api-usage-logs', [ApiKeyUsageLogController::class, 'index']);
    Route::post('/api-usage-logs', [ApiKeyUsageLogController::class, 'store']);
    Route::get('/api-usage-logs/{log}', [ApiKeyUsageLogController::class, 'show']);
    
    // Logs par utilisateur
    Route::get('/users/{userId}/api-usage-logs', [ApiKeyUsageLogController::class, 'indexByUserId']);
    
    // Statistiques et analyses
    Route::get('/api-usage-logs/statistics/global', [ApiKeyUsageLogController::class, 'statistics']);
    Route::get('/api-usage-logs/security/suspicious', [ApiKeyUsageLogController::class, 'suspicious']);
    Route::get('/api-usage-logs/analytics/performance', [ApiKeyUsageLogController::class, 'performance']);
});

// Routes internes (pour les microservices)
Route::middleware(['internal_auth'])->group(function () {
    Route::post('/internal/api-usage-logs', [ApiKeyUsageLogController::class, 'store']);
});