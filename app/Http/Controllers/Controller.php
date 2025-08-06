<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;


/**
 * @OA\Info(
 *     title="Service API",
 *     version="1.0.0",
 *     description="API de gestion des utilisateurs",
 *     @OA\Contact(
 *         email="n.taffot@elyft.tech"
 *     )
 * )
 *   @OA\Components(
 * @OA\SecurityScheme(
 * securityScheme="bearerAuth",
 * type="http",
 * scheme="bearer",
 * bearerFormat="JWT"
 * )
 * )
 * @OA\Security(
 * {"bearerAuth": {}}
 * )
 */
class Controller extends BaseController
{
    use AuthorizesRequests, ValidatesRequests;
}
