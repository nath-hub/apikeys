<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('api_key_usage_logs', function (Blueprint $table) {
            $table->uuid('id')->primary();
 
            // Relations 
            $table->uuid('user_id')->nullable();
            $table->string('public_key_id')->nullable(); // Clé publique pour identification rapide
            $table->string('private_key_id')->nullable(); // Clé publique pour identification rapide

            // Informations de la requête
            $table->string('action')->nullable()->index(); // payments.create, refunds.read, etc.
            $table->string('endpoint')->nullable(); // /api/payments, /api/refunds/123
            $table->string('http_method', 10)->default('POST'); // GET, POST, PUT, DELETE
            $table->uuid('request_uuid')->index(); // UUID fourni par le client
            $table->string('request_id')->nullable(); // ID de requête interne

            // Informations techniques
            $table->ipAddress('ip_address');
            $table->text('user_agent')->nullable();
            $table->string('country_code')->nullable(); // Code pays basé sur IP
            $table->string('environment', 20)->default('test'); // test, live, sandbox

            // Métadonnées de performance
            $table->integer('response_time_ms')->nullable(); // Temps de réponse en millisecondes
            $table->integer('response_status_code')->nullable(); // 200, 401, 500, etc.
            $table->bigInteger('request_size_bytes')->nullable(); // Taille de la requête
            $table->bigInteger('response_size_bytes')->nullable(); // Taille de la réponse

            // Informations de sécurité
            $table->boolean('signature_valid')->default(true);
            $table->string('source_service')->nullable(); // Service à l'origine de l'appel
            $table->json('request_headers')->nullable(); // Headers importants (sans données sensibles)
            $table->decimal('amount', 15, 2)->nullable(); // Montant si transaction financière
            $table->string('currency', 3)->nullable(); // Devise si transaction financière

            // Statut et flags
            $table->enum('status', ['success', 'failed', 'blocked', 'rate_limited'])->default('success');
            $table->boolean('is_suspicious')->default(false)->index(); // Marquage d'activité suspecte
            $table->text('error_message')->nullable(); // Message d'erreur si échec
            $table->string('error_code')->nullable(); // Code d'erreur technique

            // Géolocalisation (optionnel)
            $table->string('city')->nullable();
            $table->string('region')->nullable();
            $table->decimal('latitude', 10, 8)->nullable();
            $table->decimal('longitude', 11, 8)->nullable();

            // Timestamps
            $table->timestamp('created_at')->index();
            $table->timestamp('processed_at')->nullable(); // Quand le log a été traité

            // Index composites pour les performances 
            $table->index(['user_id', 'created_at']);
            $table->index(['user_id', 'action', 'created_at']);
            $table->index(['environment', 'created_at']);
            $table->index(['status', 'created_at']);
            $table->index(['is_suspicious', 'created_at']);
            $table->index(['ip_address', 'created_at']);

            // Index pour analytics
            $table->index(['action', 'status', 'created_at']);
            $table->index(['country_code', 'created_at']);
 
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('api_key_usage_logs');
    }
};
