<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * `blocked_ips.ip` is treated as a logical single row per IP (blocks are
     * refreshed, never duplicated). A unique index lets block writes use an
     * atomic upsert (INSERT ... ON DUPLICATE KEY UPDATE / ON CONFLICT) instead
     * of updateOrCreate()'s SELECT + INSERT/UPDATE, which held a gap lock and
     * helped trigger ip_behaviors deadlocks.
     */
    public function up(): void
    {
        Schema::table('blocked_ips', function (Blueprint $table) {
            $table->unique('ip', 'blocked_ips_ip_unique');
        });
    }

    public function down(): void
    {
        Schema::table('blocked_ips', function (Blueprint $table) {
            $table->dropUnique('blocked_ips_ip_unique');
        });
    }
};
