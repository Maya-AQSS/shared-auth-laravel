<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Maya\Auth\Support\JwtSubject;

// ─── fromRequest ──────────────────────────────────────────────────────────────

it('returns the id string when jwt_user is a valid array with a non-empty id', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', ['id' => 'abc-123', 'email' => 'user@example.com']);

    expect(JwtSubject::fromRequest($request))->toBe('abc-123');
});

it('returns null when jwt_user attribute is not set', function () {
    $request = Request::create('/test', 'GET');

    expect(JwtSubject::fromRequest($request))->toBeNull();
});

it('returns null when jwt_user is null', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', null);

    expect(JwtSubject::fromRequest($request))->toBeNull();
});

it('returns null when jwt_user is a non-array value', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', 'some-string');

    expect(JwtSubject::fromRequest($request))->toBeNull();
});

it('returns null when jwt_user has no id key', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', ['email' => 'user@example.com']);

    expect(JwtSubject::fromRequest($request))->toBeNull();
});

it('returns null when id is an empty string', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', ['id' => '']);

    expect(JwtSubject::fromRequest($request))->toBeNull();
});

it('returns null when id is not a string (integer)', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', ['id' => 42]);

    expect(JwtSubject::fromRequest($request))->toBeNull();
});

it('returns null when id is null inside jwt_user', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', ['id' => null]);

    expect(JwtSubject::fromRequest($request))->toBeNull();
});

// ─── claims ───────────────────────────────────────────────────────────────────

it('returns the full claims array when jwt_user is valid', function () {
    $claims = ['id' => 'user-1', 'email' => 'a@b.com', 'roles' => ['admin']];
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', $claims);

    expect(JwtSubject::claims($request))->toBe($claims);
});

it('returns empty array when jwt_user attribute is not set', function () {
    $request = Request::create('/test', 'GET');

    expect(JwtSubject::claims($request))->toBe([]);
});

it('returns empty array when jwt_user is null', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', null);

    expect(JwtSubject::claims($request))->toBe([]);
});

it('returns empty array when jwt_user is not an array', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', 'not-an-array');

    expect(JwtSubject::claims($request))->toBe([]);
});
