<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Maya\Auth\Dtos\JwtProfileDto;

// ─── fromArray ────────────────────────────────────────────────────────────────

it('builds a DTO from a valid array with id and claims', function () {
    $dto = JwtProfileDto::fromArray(['id' => 'user-1', 'email' => 'a@b.com', 'roles' => ['admin']]);

    expect($dto)->not->toBeNull();
    expect($dto->id)->toBe('user-1');
    expect($dto->claims['email'])->toBe('a@b.com');
    expect($dto->claims['roles'])->toBe(['admin']);
});

it('returns null from fromArray when id is missing', function () {
    expect(JwtProfileDto::fromArray(['email' => 'a@b.com']))->toBeNull();
});

it('returns null from fromArray when id is an empty string', function () {
    expect(JwtProfileDto::fromArray(['id' => '']))->toBeNull();
});

it('returns null from fromArray when id is not a string', function () {
    expect(JwtProfileDto::fromArray(['id' => 42]))->toBeNull();
});

it('returns null from fromArray when array is empty', function () {
    expect(JwtProfileDto::fromArray([]))->toBeNull();
});

it('preserves all extra claims in the claims property', function () {
    $input = ['id' => 'u1', 'locale' => 'es', 'org_id' => 'org-99', 'custom' => true];
    $dto = JwtProfileDto::fromArray($input);

    expect($dto)->not->toBeNull();
    expect($dto->claims)->toBe($input);
});

// ─── fromRequestAttribute ─────────────────────────────────────────────────────

it('builds a DTO from a valid request with jwt_user attribute', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', ['id' => 'req-user', 'email' => 'req@test.com']);

    $dto = JwtProfileDto::fromRequestAttribute($request);

    expect($dto)->not->toBeNull();
    expect($dto->id)->toBe('req-user');
    expect($dto->claims['email'])->toBe('req@test.com');
});

it('returns null from fromRequestAttribute when jwt_user attribute is not set', function () {
    $request = Request::create('/test', 'GET');

    expect(JwtProfileDto::fromRequestAttribute($request))->toBeNull();
});

it('returns null from fromRequestAttribute when jwt_user is null', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', null);

    expect(JwtProfileDto::fromRequestAttribute($request))->toBeNull();
});

it('returns null from fromRequestAttribute when id is empty', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', ['id' => '']);

    expect(JwtProfileDto::fromRequestAttribute($request))->toBeNull();
});

it('returns null from fromRequestAttribute when jwt_user is not an array', function () {
    $request = Request::create('/test', 'GET');
    $request->attributes->set('jwt_user', 'malformed');

    expect(JwtProfileDto::fromRequestAttribute($request))->toBeNull();
});

// ─── Immutability / readonly ──────────────────────────────────────────────────

it('DTO is readonly — cannot reassign id', function () {
    $dto = JwtProfileDto::fromArray(['id' => 'u1']);

    expect(fn () => $dto->id = 'mutated')
        ->toThrow(Error::class);
});

// ─── Extensibility pattern ────────────────────────────────────────────────────

it('all extra claims are accessible via the claims array for subclass extension', function () {
    $extra = ['study_type_ids' => ['st-1', 'st-2'], 'department' => 'IT'];
    $dto = JwtProfileDto::fromArray(array_merge(['id' => 'u2'], $extra));

    expect($dto->claims['study_type_ids'])->toBe(['st-1', 'st-2']);
    expect($dto->claims['department'])->toBe('IT');
});
