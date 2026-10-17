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
            $table->index(['event_type', 'severity'], 'security_events_event_type_severity_index');
            $table->dropIndex('security_events_event_type_index');
        });

        Schema::table('blocked_ips', function (Blueprint $table) {
            $table->dropIndex('blocked_ips_ip_index');
        });
    }

    public function down(): void
    {
        Schema::table('blocked_ips', function (Blueprint $table) {
            $table->index('ip', 'blocked_ips_ip_index');
        });

        Schema::table('security_events', function (Blueprint $table) {
            $table->index('event_type', 'security_events_event_type_index');
            $table->dropIndex('security_events_event_type_severity_index');
        });
    }
};
