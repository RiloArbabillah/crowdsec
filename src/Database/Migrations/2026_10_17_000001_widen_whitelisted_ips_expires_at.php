<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * MySQL/MariaDB TIMESTAMP columns end at 2038-01-19, so a whitelist entry
     * expiring later failed to save. DATETIME has no such limit. Other
     * drivers' timestamp types are already wide enough. Raw SQL because
     * Blueprint::change() needs doctrine/dbal on Laravel 10.
     */
    public function up(): void
    {
        $this->modifyExpiresAt('DATETIME NULL');
    }

    public function down(): void
    {
        // Clamp values TIMESTAMP cannot hold before narrowing the column.
        $this->whenMysql(fn (string $table) => DB::table($table)
            ->where('expires_at', '>', '2038-01-19 03:14:07')
            ->update(['expires_at' => '2038-01-19 03:14:07']));

        $this->modifyExpiresAt('TIMESTAMP NULL');
    }

    protected function modifyExpiresAt(string $definition): void
    {
        $this->whenMysql(function (string $table) use ($definition): void {
            $prefixed = Schema::getConnection()->getTablePrefix() . $table;

            DB::statement("ALTER TABLE `{$prefixed}` MODIFY `expires_at` {$definition}");
        });
    }

    protected function whenMysql(\Closure $callback): void
    {
        if (in_array(Schema::getConnection()->getDriverName(), ['mysql', 'mariadb'], true)) {
            $callback('whitelisted_ips');
        }
    }
};
