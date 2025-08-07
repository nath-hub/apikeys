<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('api_keys', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('key_id')->unique();
            $table->string('key_hash');     

            // Relations
            $table->string('user_id');
            $table->string('entreprise_id');

            // Types et environnements
            $table->enum('key_type', ['public', 'private']);
            $table->enum('environment', ['test', 'live', 'sandbox'])->default('test');

            // Métadonnées
            $table->string('name', 100)->nullable();
            $table->text('description')->nullable();

            // Sécurité et permissions
            $table->json('permissions')->nullable();
            $table->json('ip_whitelist')->nullable();
            $table->json('domain_whitelist')->nullable();

            // Gestion du cycle de vie
            $table->enum('status', ['active', 'inactive', 'revoked', 'expired'])->default('active');
            $table->timestamp('expires_at')->nullable();

            // Monitoring
            $table->timestamp('last_used_at')->nullable();
            $table->string('last_used_ip', 45)->nullable();
            $table->bigInteger('usage_count')->default(0);
            $table->integer('rate_limit_per_minute')->default(1000);

            // Audit
            $table->timestamps();
            $table->string('created_by')->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->string('revoked_by')->nullable();
            $table->text('revocation_reason')->nullable();

            // Index
            // $table->index(['user_id', 'company_id']);
            $table->index(['key_type', 'environment']);
            $table->index(['status', 'expires_at']);
            $table->index('last_used_at');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('api_keys');
    }
};
