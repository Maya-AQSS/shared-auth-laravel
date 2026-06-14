<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Maya\Auth\Middleware\RequirePermissionMiddleware;

function permRequest(?array $jwtUser): Request
{
    $request = Request::create('/api/test', 'GET');
    if ($jwtUser !== null) {
        $request->attributes->set('jwt_user', $jwtUser);
    }
    return $request;
}

function permMiddleware(): RequirePermissionMiddleware
{
    return new RequirePermissionMiddleware();
}

beforeEach(function () {
    Cache::flush();
});

// ─── Fail closed: no authenticated user ──────────────────────────────────────

it('returns 401 when jwt_user attribute is missing (fail closed)', function () {
    $called = false;
    $response = permMiddleware()->handle(
        permRequest(null),
        function ($r) use (&$called) {
            $called = true;
            return response()->json(['ok' => true]);
        },
        'alerts.manage',
    );

    expect($response->getStatusCode())->toBe(401);
    expect($called)->toBeFalse();
});

// ─── Authenticated but missing permission ────────────────────────────────────

it('returns 403 without leaking the permission slug when permission is missing', function () {
    DB::shouldReceive('table->where->where->exists')->andReturn(false);

    $response = permMiddleware()->handle(
        permRequest(['id' => 'user-1']),
        fn ($r) => response()->json(['ok' => true]),
        'alerts.manage',
    );

    expect($response->getStatusCode())->toBe(403);
    expect($response->getContent())->not->toContain('alerts.manage');
});

// ─── Authenticated with permission ───────────────────────────────────────────

it('passes through when the user has the permission', function () {
    DB::shouldReceive('table->where->where->exists')->andReturn(true);

    $called = false;
    $response = permMiddleware()->handle(
        permRequest(['id' => 'user-1']),
        function ($r) use (&$called) {
            $called = true;
            return response()->json(['ok' => true]);
        },
        'alerts.manage',
    );

    expect($called)->toBeTrue();
    expect($response->getStatusCode())->toBe(200);
});
