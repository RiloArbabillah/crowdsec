<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('security_events', function (Blueprint $table) {
            $table->string('request_id', 128)->nullable()->index();
            $table->string('route_name')->nullable()->index();
            $table->string('content_type')->nullable();
            $table->unsignedBigInteger('content_length')->nullable();
            $table->unsignedSmallInteger('response_status')->nullable();
            $table->unsignedInteger('duration_ms')->nullable();
            $table->string('action_taken', 32)->nullable()->index();
            $table->char('country_code', 2)->nullable()->index();
            $table->unsignedBigInteger('asn')->nullable()->index();
            $table->string('isp')->nullable();
            $table->char('authenticated_user_id_hash', 64)->nullable()->index();
            $table->string('browser')->nullable();
            $table->string('os')->nullable();
            $table->string('device_type', 64)->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('security_events', function (Blueprint $table) {
            $table->dropIndex(['request_id']);
            $table->dropIndex(['route_name']);
            $table->dropIndex(['action_taken']);
            $table->dropIndex(['country_code']);
            $table->dropIndex(['asn']);
            $table->dropIndex(['authenticated_user_id_hash']);
            $table->dropColumn([
                'request_id',
                'route_name',
                'content_type',
                'content_length',
                'response_status',
                'duration_ms',
                'action_taken',
                'country_code',
                'asn',
                'isp',
                'authenticated_user_id_hash',
                'browser',
                'os',
                'device_type',
            ]);
        });
    }
};
