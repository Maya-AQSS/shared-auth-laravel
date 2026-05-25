<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Maya\Auth\Contracts\JwksServiceInterface;
use Maya\Auth\JwksService;
use Maya\Auth\Middleware\JwtMiddleware;

function makeRequest(?string $token = null): Request
{
    $request = Request::create('/api/test', 'GET');
    if ($token !== null) {
        $request->headers->set('Authorization', "Bearer {$token}");
    }
    return $request;
}

function loadToken(string $name): string
{
    return trim(file_get_contents(__DIR__ . "/../Fixtures/{$name}.txt"));
}

function jwtMiddleware(): JwtMiddleware
{
    return app(JwtMiddleware::class);
}

beforeEach(function () {
    Http::fake(['*' => Http::response(json_decode(
        file_get_contents(__DIR__ . '/../Fixtures/jwks.json'),
        true
    ), 200)]);
    Cache::flush();
});

// ─── Missing token ─────────────────────────────────────────────────────────

it('returns 401 when Authorization header is missing', function () {
    $response = jwtMiddleware()->handle(makeRequest(), fn ($r) => response()->json(['ok' => true]));
    expect($response->getStatusCode())->toBe(401);
});

it('returns 401 when Authorization is not Bearer format', function () {
    $request = makeRequest();
    $request->headers->set('Authorization', 'Basic dXNlcjpwYXNz');
    $response = jwtMiddleware()->handle($request, fn ($r) => response()->json(['ok' => true]));
    expect($response->getStatusCode())->toBe(401);
});

// ─── Valid token ───────────────────────────────────────────────────────────

it('passes through and sets jwt_user for valid token', function () {
    $token = loadToken('jwt-valid');
    $request = makeRequest($token);

    $called = false;
    $response = jwtMiddleware()->handle($request, function ($r) use (&$called) {
        $called = true;
        $jwtUser = $r->attributes->get('jwt_user');
        expect($jwtUser)->not->toBeNull();
        expect($jwtUser['id'])->toBe('test-user-uuid-0001');
        return response()->json(['ok' => true]);
    });

    expect($called)->toBeTrue();
    expect($response->getStatusCode())->toBe(200);
});

// ─── Expired token ─────────────────────────────────────────────────────────

it('returns 401 for expired token', function () {
    $token = loadToken('jwt-expired');
    $response = jwtMiddleware()->handle(makeRequest($token), fn ($r) => response()->json(['ok' => true]));
    expect($response->getStatusCode())->toBe(401);
});

it('logs expired token at info level with JWT-EXPIRED code (not warning)', function () {
    $logged = [];
    Log::listen(function ($event) use (&$logged) {
        $logged[] = [
            'level'   => $event->level,
            'message' => $event->message,
            'context' => $event->context,
        ];
    });

    $token = loadToken('jwt-expired');
    jwtMiddleware()->handle(makeRequest($token), fn ($r) => response()->json(['ok']));

    $entry = collect($logged)->first(fn ($e) => $e['message'] === 'JWT authentication failed');
    expect($entry)->not->toBeNull();
    expect($entry['level'])->toBe('info');
    expect($entry['context']['error_code'])->toBe('JWT-EXPIRED');
});

it('logs malformed/invalid token at warning level with JWT-INVALID code', function () {
    $logged = [];
    Log::listen(function ($event) use (&$logged) {
        $logged[] = [
            'level'   => $event->level,
            'message' => $event->message,
            'context' => $event->context,
        ];
    });

    jwtMiddleware()->handle(makeRequest('not.a.valid.jwt.at.all'), fn ($r) => response()->json(['ok']));

    $entry = collect($logged)->first(fn ($e) => $e['message'] === 'JWT authentication failed');
    expect($entry)->not->toBeNull();
    expect($entry['level'])->toBe('warning');
    expect($entry['context']['error_code'])->toBe('JWT-INVALID');
});

// ─── Unknown kid ───────────────────────────────────────────────────────────

it('returns 401 for token with unknown kid', function () {
    // Bind a JwksService that always throws — avoids Http::fake stacking issues in beforeEach
    $this->instance(JwksServiceInterface::class, new class implements JwksServiceInterface {
        public function getPublicKey(string $kid): string {
            throw new \RuntimeException("JWKS key not found for kid: {$kid}");
        }
    });

    $token = loadToken('jwt-valid');
    $response = app(JwtMiddleware::class)->handle(makeRequest($token), fn ($r) => response()->json(['ok' => true]));
    expect($response->getStatusCode())->toBe(401);
});

// ─── Malformed token ───────────────────────────────────────────────────────

it('returns 401 for malformed JWT (not 3 parts)', function () {
    $response = jwtMiddleware()->handle(makeRequest('not.a.valid.jwt.at.all'), fn ($r) => response()->json(['ok']));
    expect($response->getStatusCode())->toBe(401);
});

// ─── Audience validation ───────────────────────────────────────────────────

it('returns 401 for token with wrong audience', function () {
    $token = loadToken('jwt-wrong-audience');
    $response = jwtMiddleware()->handle(makeRequest($token), fn ($r) => response()->json(['ok' => true]));
    expect($response->getStatusCode())->toBe(401);
});

it('throws RuntimeException in non-testing env when jwt_audience is empty', function () {
    config(['auth.jwt_audience' => '']);

    app()->detectEnvironment(fn () => 'production');
    try {
        $token = loadToken('jwt-valid');
        expect(fn () => jwtMiddleware()->handle(makeRequest($token), fn ($r) => response()->json(['ok']))
        )->toThrow(RuntimeException::class, 'AUTH_JWT_AUDIENCE is not configured');
    } finally {
        app()->detectEnvironment(fn () => 'testing');
    }
});

it('skips audience check silently in testing env when jwt_audience is empty', function () {
    config(['auth.jwt_audience' => '']);

    $token = loadToken('jwt-valid');
    $response = jwtMiddleware()->handle(makeRequest($token), fn ($r) => response()->json(['ok' => true]));
    // In testing env, empty audience is allowed (graceful skip)
    expect($response->getStatusCode())->toBe(200);
});

// ─── DEV_BYPASS_AUTH ──────────────────────────────────────────────────────

it('bypasses auth when dev_bypass_auth=true and env=local', function () {
    config(['auth.dev_bypass_auth' => true]);
    app()->detectEnvironment(fn () => 'local');

    try {
        $called = false;
        $response = jwtMiddleware()->handle(makeRequest(null), function ($r) use (&$called) {
            $called = true;
            $jwtUser = $r->attributes->get('jwt_user');
            expect($jwtUser['email'])->toBe('dev@maya.localhost');
            return response()->json(['ok' => true]);
        });

        expect($called)->toBeTrue();
    } finally {
        app()->detectEnvironment(fn () => 'testing');
    }
});

it('does NOT bypass auth when dev_bypass_auth=true but env=production', function () {
    config(['auth.dev_bypass_auth' => true]);
    app()->detectEnvironment(fn () => 'production');

    try {
        $response = jwtMiddleware()->handle(makeRequest(null), fn ($r) => response()->json(['ok']));
        expect($response->getStatusCode())->toBe(401);
    } finally {
        app()->detectEnvironment(fn () => 'testing');
    }
});

// ─── Redis cache of user profile ────────────────────────────────────────────

it('caches user profile in array store after successful validation', function () {
    $token = loadToken('jwt-valid');
    jwtMiddleware()->handle(makeRequest($token), fn ($r) => response()->json(['ok']));

    expect(Cache::has('jwt_user:test-user-uuid-0001'))->toBeTrue();
});

it('reuses cached user profile on second request without re-parsing JWT', function () {
    $token = loadToken('jwt-valid');
    $middleware = jwtMiddleware();

    $middleware->handle(makeRequest($token), fn ($r) => response()->json(['ok']));
    $middleware->handle(makeRequest($token), fn ($r) => response()->json(['ok']));

    // JWKS was only fetched once (cache hit on second call too)
    Http::assertSentCount(1);
});
