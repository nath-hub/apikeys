<?php

namespace App\Console\Commands;

use App\Http\Services\ApiKeyService;
use Illuminate\Console\Command;
use App\Models\ApiKeys as apiKey;

class Apikeys extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'apikeys:check';

    protected $description = 'Vérifie et expire les clés API qui ont dépassé leur date d\'expiration';

    protected $apiKeyService;

    public function __construct(ApiKeyService $apiKeyService)
    {
        parent::__construct();
        $this->apiKeyService = $apiKeyService;
    }

    /**
     * Execute the console command.
     */
    public function handle()
    {

        $this->info('Vérification des clés API expirées...');

        $result = $this->apiKeyService->checkAndExpireKeys();

        $this->info("Clés vérifiées: {$result['total_checked']}");
        $this->info("Clés expirées: {$result['expired_count']}");

        if (!empty($result['errors'])) {
            $this->error("Erreurs rencontrées: " . count($result['errors']));
            foreach ($result['errors'] as $error) {
                $this->error("- " . ($error['key_id'] ?? 'Général') . ": " . $error['error']);
            }
        }

        $this->info('Nettoyage du cache rate limit...');

        $this->apiKeyService->cleanupRateLimitCache();

        $this->info('Nettoyage terminé.');


        // $keyId = $this->argument('key-id');

        $keys = apiKey::where('status', 'active')
            ->whereNotNull('expires_at')
            ->where('expires_at', '<=', now())->get();

        foreach ($keys as $key) {


            $stats = $this->apiKeyService->getKeyUsageStats($key->id);

            if (isset($stats['error'])) {
                $this->error("Erreur: " . $stats['error']);
                return 1;
            }

            $this->info("=== Statistiques pour la clé: {$key->id} ===");
            $this->line("Statut: " . $stats['status']);
            $this->line("Utilisations: " . number_format($stats['usage_count']));
            $this->line("Dernière utilisation: " . ($stats['last_used_at'] ?? 'Jamais'));
            $this->line("Dernière IP: " . ($stats['last_used_ip'] ?? 'Aucune'));
            $this->line("Rate limit/minute: " . $stats['rate_limit_per_minute']);
            $this->line("Expire le: " . ($stats['expires_at'] ?? 'Jamais'));

            if ($stats['days_until_expiry'] !== null) {
                if ($stats['days_until_expiry'] > 0) {
                    $this->info("Jours avant expiration: " . $stats['days_until_expiry']);
                } else {
                    $this->error("EXPIRÉE depuis " . abs($stats['days_until_expiry']) . " jours");
                }
            }

            $this->line("IPs en whitelist: " . (count($stats['ip_whitelist'] ?? []) ?: 'Aucune'));
            $this->line("Domaines en whitelist: " . (count($stats['domain_whitelist'] ?? []) ?: 'Aucun'));


        }

        return 0;
    }
}
