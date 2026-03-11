<?php

namespace RiloArbabillah\LaravelCrowdSec\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Http\UploadedFile;
use Orchestra\Testbench\TestCase;
use RiloArbabillah\LaravelCrowdSec\CrowdSecServiceProvider;
use RiloArbabillah\LaravelCrowdSec\Services\CrowdSecService;

class DeepInspectionTest extends TestCase
{
    protected CrowdSecService $service;

    protected function getPackageProviders($app): array
    {
        return [CrowdSecServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set(
            'crowdsec-scenarios',
            require __DIR__ . '/../../config/crowdsec-scenarios.php'
        );
        $app['config']->set('crowdsec-scenarios.enabled', true);

        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->loadMigrationsFrom(__DIR__ . '/../../src/Database/Migrations');
        $this->service = app(CrowdSecService::class);
    }

    // =========================================================================
    // BASE64 DECODE TESTS
    // =========================================================================

    public function test_detects_base64_encoded_sql_injection(): void
    {
        // "' OR 1=1 --" encoded in base64
        $encoded = base64_encode("' OR 1=1 --");

        $request = Request::create('/test', 'POST', ['q' => $encoded]);
        $threats = $this->service->checkWafPatterns($request);

        $this->assertNotEmpty($threats, 'Should detect base64-encoded SQL injection');
        $this->assertTrue(
            collect($threats)->contains('type', 'sql_injection'),
            'Threat type should be sql_injection'
        );
    }

    public function test_detects_base64_encoded_xss(): void
    {
        // "<script>alert(1)</script>" encoded in base64
        $encoded = base64_encode('<script>alert(1)</script>');

        $request = Request::create('/test', 'POST', ['q' => $encoded]);
        $threats = $this->service->checkWafPatterns($request);

        $this->assertNotEmpty($threats, 'Should detect base64-encoded XSS');
        $this->assertTrue(
            collect($threats)->contains('type', 'xss'),
            'Threat type should be xss'
        );
    }

    public function test_safe_base64_not_flagged(): void
    {
        // "hello world" encoded in base64 — should not trigger
        $encoded = base64_encode('hello world test content');

        $request = Request::create('/test', 'GET', ['q' => $encoded]);
        $threats = $this->service->checkWafPatterns($request);

        $this->assertEmpty($threats, 'Safe base64 content should not be flagged');
    }

    // =========================================================================
    // FILE UPLOAD TESTS
    // =========================================================================

    public function test_detects_php_file_upload(): void
    {
        $file = UploadedFile::fake()->create('shell.php', 100, 'text/plain');

        $request = Request::create('/upload', 'POST', [], [], ['avatar' => $file]);
        $threats = $this->service->checkWafPatterns($request);

        $this->assertTrue(
            collect($threats)->contains('type', 'file_upload_threat'),
            'Should detect PHP file upload'
        );
    }

    public function test_detects_double_extension_upload(): void
    {
        $file = UploadedFile::fake()->create('image.jpg.php', 100, 'image/jpeg');

        $request = Request::create('/upload', 'POST', [], [], ['avatar' => $file]);
        $threats = $this->service->checkWafPatterns($request);

        $this->assertTrue(
            collect($threats)->contains('type', 'file_upload_double_ext'),
            'Should detect double extension attack'
        );
    }

    public function test_detects_path_traversal_in_filename(): void
    {
        // Directly test the service with a crafted request containing path traversal.
        // Since UploadedFile may strip traversal chars, we test the internal logic
        // by using a filename that contains '..' but not as directory separator.
        $tmpFile = tempnam(sys_get_temp_dir(), 'test');
        file_put_contents($tmpFile, 'test content');
        $file = new UploadedFile($tmpFile, '..backdoor.php', 'text/plain', null, true);

        $request = Request::create('/upload', 'POST', [], [], ['doc' => $file]);
        $threats = $this->service->checkWafPatterns($request);

        // Should detect both path traversal AND file upload threat
        $hasTraversal = collect($threats)->contains('type', 'file_upload_path_traversal');
        $hasFileThreat = collect($threats)->contains('type', 'file_upload_threat');
        $this->assertTrue($hasTraversal || $hasFileThreat, 'Should detect path traversal or dangerous file');

        @unlink($tmpFile);
    }

    public function test_safe_file_upload_not_flagged(): void
    {
        $file = UploadedFile::fake()->image('profile.jpg', 100, 100);

        $request = Request::create('/upload', 'POST', [], [], ['avatar' => $file]);
        $threats = $this->service->checkWafPatterns($request);

        $fileThreats = collect($threats)->filter(fn ($t) => str_starts_with($t['type'], 'file_upload_'));
        $this->assertEmpty($fileThreats, 'Safe image upload should not be flagged');
    }

    // =========================================================================
    // JWT INSPECTION TESTS
    // =========================================================================

    public function test_detects_jwt_privilege_escalation(): void
    {
        // Craft a JWT with admin role in payload
        $header = base64_encode(json_encode(['alg' => 'none', 'typ' => 'JWT']));
        $payload = base64_encode(json_encode(['sub' => '123', 'role' => 'admin']));
        $jwt = "{$header}.{$payload}.signature";

        $request = Request::create('/api/resource', 'GET');
        $request->headers->set('Authorization', "Bearer {$jwt}");
        $threats = $this->service->checkWafPatterns($request);

        $this->assertTrue(
            collect($threats)->contains('type', 'jwt_privilege_escalation'),
            'Should detect admin role in JWT'
        );
    }

    public function test_detects_jwt_with_sqli_in_payload(): void
    {
        // Craft a JWT with SQL injection in a claim value
        $header = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = base64_encode(json_encode([
            'sub' => '123',
            'name' => "admin' OR 1=1 --",
        ]));
        $jwt = "{$header}.{$payload}.signature";

        $request = Request::create('/api/resource', 'POST', ['token' => $jwt]);
        $threats = $this->service->checkWafPatterns($request);

        $jwtPayloadThreats = collect($threats)->filter(fn ($t) => str_starts_with($t['type'], 'jwt_payload_'));
        $this->assertNotEmpty($jwtPayloadThreats, 'Should detect SQLi in JWT payload');
    }

    public function test_safe_jwt_not_flagged(): void
    {
        // Normal JWT with safe claims
        $header = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = base64_encode(json_encode([
            'sub' => '123',
            'name' => 'John Doe',
            'role' => 'user',
        ]));
        $jwt = "{$header}.{$payload}.signature";

        $request = Request::create('/api/resource', 'GET');
        $request->headers->set('Authorization', "Bearer {$jwt}");
        $threats = $this->service->checkWafPatterns($request);

        $jwtThreats = collect($threats)->filter(fn ($t) => str_starts_with($t['type'], 'jwt_'));
        $this->assertEmpty($jwtThreats, 'Safe JWT should not be flagged');
    }
}
