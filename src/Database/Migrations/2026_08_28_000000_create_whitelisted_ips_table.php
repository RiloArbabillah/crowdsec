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
        Schema::create('whitelisted_ips', function (Blueprint $table) {
            $table->id();
            $table->string('ip', 45)->index();
            $table->string('label', 100)->nullable();
            $table->text('note')->nullable();
            $table->boolean('is_active')->default(true)->index();
            $table->timestamp('expires_at')->nullable()->index();
            $table->unsignedBigInteger('created_by')->nullable();
            $table->string('created_by_label', 100)->nullable();
            $table->timestamps();

            $table->index(['is_active', 'expires_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('whitelisted_ips');
    }
};
