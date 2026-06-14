<?php

use Illuminate\Http\Request;
use Maya\Auth\Middleware\RequireRoleMiddleware;

function roleRequest(?array $jwtUser): Request
{
    $request = Request::create('/api/test', 'GET');
    if ($jwtUser !== null) {
        $request->attributes->set('jwt_user', $jwtUser);
    }
    return $request;
}

function roleMiddleware(): RequireRoleMiddleware
{
    return new RequireRoleMiddleware();
}

// ─── Fail closed: no authenticated user ──────────────────────────────────────

it('returns 401 when jwt_user attribute is missing (fail closed)', function () {
    $called = false;
    $response = roleMiddleware()->handle(
        roleRequest(null),
        function ($r) use (&$called) {
            $called = true;
            return response()->json(['ok' => true]);
        },
        'admin',
    );

    expect($response->getStatusCode())->toBe(401);
    expect($called)->toBeFalse();
});

// ─── Authenticated with a matching role ──────────────────────────────────────

it('passes through when the user has one of the required roles', function () {
    $called = false;
    $response = roleMiddleware()->handle(
        roleRequest(['id' => 'user-1', 'roles' => ['user', 'admin']]),
        function ($r) use (&$called) {
            $called = true;
            return response()->json(['ok' => true]);
        },
        'admin',
        'super-admin',
    );

    expect($called)->toBeTrue();
    expect($response->getStatusCode())->toBe(200);
});

// ─── Authenticated without any matching role ─────────────────────────────────

it('returns 403 when the user has none of the required roles', function () {
    $response = roleMiddleware()->handle(
        roleRequest(['id' => 'user-1', 'roles' => ['user']]),
        fn ($r) => response()->json(['ok' => true]),
        'admin',
    );

    expect($response->getStatusCode())->toBe(403);
});
