<?php

namespace App\Console\Commands;

use App\Models\ApiKeyUsageLog;
use Carbon\Carbon;
use Illuminate\Console\Command;

class CleanOldApiUsageLogs extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
     protected $signature = 'api-logs:clean 
                            {--days=90 : Number of days to keep}
                            {--batch-size=1000 : Number of records to delete per batch}
                            {--dry-run : Show what would be deleted without actually deleting}';

    protected $description = 'Clean old API usage logs to free up database space';

    public function handle(): int
    {
        $days = $this->option('days');
        $batchSize = $this->option('batch-size');
        $dryRun = $this->option('dry-run');
        
        $cutoffDate = Carbon::now()->subDays($days);
        
        $query = ApiKeyUsageLog::where('created_at', '<', $cutoffDate);
        $totalCount = $query->count();
        
        if ($totalCount === 0) {
            $this->info("No logs found older than {$days} days.");
            return self::SUCCESS;
        }
        
        $this->info("Found {$totalCount} logs older than {$days} days ({$cutoffDate->toDateString()}).");
        
        if ($dryRun) {
            $this->warn('DRY RUN: No records will be deleted.');
            
            // Afficher un échantillon
            $sample = $query->select('id', 'created_at', 'user_id', 'action')
                ->orderBy('created_at')
                ->limit(10)
                ->get();
                
            $this->table(
                ['ID', 'Created At', 'User ID', 'Action'],
                $sample->map(fn($log) => [
                    $log->id,
                    $log->created_at->toDateTimeString(),
                    $log->user_id,
                    $log->action ?? 'N/A'
                ])
            );
            
            return self::SUCCESS;
        }
        
        if (!$this->confirm("Are you sure you want to delete {$totalCount} old logs?")) {
            $this->info('Operation cancelled.');
            return self::SUCCESS;
        }
        
        $deletedCount = 0;
        $bar = $this->output->createProgressBar($totalCount);
        $bar->start();
        
        do {
            $batch = ApiKeyUsageLog::where('created_at', '<', $cutoffDate)
                ->limit($batchSize)
                ->pluck('id');
                
            if ($batch->isEmpty()) {
                break;
            }
            
            $batchDeleted = ApiKeyUsageLog::whereIn('id', $batch)->delete();
            $deletedCount += $batchDeleted;
            $bar->advance($batchDeleted);
            
            // Petite pause pour éviter de surcharger la DB
            usleep(10000); // 10ms
            
        } while ($batch->count() === $batchSize);
        
        $bar->finish();
        $this->newLine(2);
        
        $this->info("Successfully deleted {$deletedCount} old API usage logs.");
        
        return self::SUCCESS;
    }
}
