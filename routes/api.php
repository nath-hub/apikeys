<?php

use App\Http\Controllers\ApiKeysController;
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
    Route::delete('{id}/delete', [ApiKeysController::class, 'destroy'])->name('api.destroy');
});
 