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
        // Create security_events table
        Schema::create('security_events', function (Blueprint $table) {
            $table->id();
            $table->string('ip', 45)->index();
            $table->string('event_type', 100)->index();
            $table->string('severity', 20)->default('medium');
            $table->json('request_data')->nullable();
            $table->string('user_agent')->nullable();
            $table->string('request_path')->nullable();
            $table->json('matched_patterns')->nullable();
            $table->unsignedBigInteger('blocked_ip_id')->nullable();
            $table->timestamps();

            $table->index(['created_at', 'severity']);
            $table->index(['ip', 'created_at']);
        });

        // Create blocked_ips table
        Schema::create('blocked_ips', function (Blueprint $table) {
            $table->id();
            $table->string('ip', 45)->unique();
            $table->text('reason')->nullable();
            $table->string('event_type', 100)->nullable();
            $table->timestamp('expires_at')->nullable();
            $table->boolean('is_active')->default(true);
            $table->unsignedBigInteger('created_by')->nullable();
            $table->timestamps();

            $table->index(['is_active', 'expires_at']);
            $table->index(['ip', 'is_active']);
        });

        // Create ip_behaviors table
        Schema::create('ip_behaviors', function (Blueprint $table) {
            $table->id();
            $table->string('ip', 45)->unique();
            $table->unsignedInteger('request_count')->default(0);
            $table->unsignedInteger('error_404_count')->default(0);
            $table->unsignedInteger('login_attempts')->default(0);
            $table->decimal('threat_score', 5, 2)->default(0);
            $table->timestamp('first_activity')->nullable();
            $table->timestamp('last_activity')->nullable();
            $table->timestamps();

            $table->index(['last_activity']);
            $table->index(['threat_score']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('ip_behaviors');
        Schema::dropIfExists('blocked_ips');
        Schema::dropIfExists('security_events');
    }
};
