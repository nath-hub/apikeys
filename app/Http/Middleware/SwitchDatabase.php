<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Config;

class SwitchDatabase
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */

    public function handle($request, Closure $next)
    {
        $host = $request->getHost(); // exemple: client1.mondomaine.com

        if (str_contains($host, 'sandbox')) {
            Config::set('database.default', 'mysql_sandbox');
        } elseif (str_contains($host, 'backend')) {
            Config::set('database.default', 'mysql_prod');
        } else {
            Config::set('database.default', 'mysql_sandbox');
        }

        return $next($request);
    }
}
