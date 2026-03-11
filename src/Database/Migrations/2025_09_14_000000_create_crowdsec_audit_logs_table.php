<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('crowdsec_audit_logs', function (Blueprint $table) {
            $table->id();
            $table->string('action', 50)->index();       // ip_blocked, ip_unblocked, whitelist_modified, config_changed, etc.
            $table->string('actor', 100)->default('system'); // 'system' or user identifier
            $table->string('target_ip', 45)->nullable()->index();
            $table->json('metadata')->nullable();         // Extra context (reason, old_value, new_value, etc.)
            $table->timestamp('created_at')->index();     // Immutable — no updated_at
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('crowdsec_audit_logs');
    }
};
