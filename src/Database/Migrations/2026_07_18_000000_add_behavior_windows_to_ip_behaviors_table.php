<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('ip_behaviors', function (Blueprint $table) {
            $table->timestamp('request_window_started_at')->nullable()->after('request_count');
            $table->timestamp('error_404_window_started_at')->nullable()->after('error_404_count');
            $table->timestamp('login_window_started_at')->nullable()->after('login_attempts');
        });
    }

    public function down(): void
    {
        Schema::table('ip_behaviors', function (Blueprint $table) {
            $table->dropColumn([
                'request_window_started_at',
                'error_404_window_started_at',
                'login_window_started_at',
            ]);
        });
    }
};
