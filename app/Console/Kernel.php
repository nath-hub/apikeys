<?php

namespace App\Console;

use App\Http\Controllers\ApiKeyUsageLogController;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\Log;

class Kernel extends ConsoleKernel
{
    /**
     * Define the application's command schedule.
     */
    protected function schedule(Schedule $schedule): void
    {
        // $schedule->command('inspire')->hourly();
        $schedule->command('api-logs:clean --days=90')
            ->weekly()
            ->sundays()
            ->at('02:00')
            ->appendOutputTo(storage_path('logs/api-logs-cleanup.log'));

        // Générer un rapport hebdomadaire d'utilisation
        $schedule->call(function () {
            // Logique pour générer un rapport hebdomadaire
            $stats = app(ApiKeyUsageLogController::class)->getGlobalStatistics('week', null);
            Log::info('Weekly API usage report', $stats);
        })->weekly()->mondays()->at('09:00');
    }

    /**
     * Register the commands for the application.
     */
    protected function commands(): void
    {
        $this->load(__DIR__ . '/Commands');

        require base_path('routes/console.php');
    }
}
