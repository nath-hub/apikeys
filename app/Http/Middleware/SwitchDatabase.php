<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Config;

class SwitchDatabase
{
    public function handle($request, Closure $next)
    {
        $host = $request->getHost(); // exemple: client1.mondomaine.com

        if (str_contains($host, 'client1')) {
            Config::set('database.default', 'mysql_client1');
        } elseif (str_contains($host, 'client2')) {
            Config::set('database.default', 'mysql_client2');
        }else {
            Config::set('database.default', 'mysql');
        }

        return $next($request);
    }
}

