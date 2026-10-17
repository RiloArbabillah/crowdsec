<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * - `security_events (event_type, severity)` serves the metrics endpoint's
     *   GROUP BY as an index-only scan and replaces the single-column
     *   `event_type` index (its prefix).
     * - `blocked_ips.ip` already has a unique index, so the plain index on the
     *   same column only costs writes.
     */
    public function up(): void
    {
        Schema::table('security_events', function (Blueprint $table) {
            // Column forms so Laravel derives prefixed index names (prefix_indexes)
            $table->index(['event_type', 'severity']);
            $table->dropIndex(['event_type']);
        });

        Schema::table('blocked_ips', function (Blueprint $table) {
            $table->dropIndex(['ip']);
        });
    }

    public function down(): void
    {
        Schema::table('blocked_ips', function (Blueprint $table) {
            $table->index('ip');
        });

        Schema::table('security_events', function (Blueprint $table) {
            $table->index('event_type');
            $table->dropIndex(['event_type', 'severity']);
        });
    }
};
