<?php

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Maya\Auth\JwksService;

$fixtureDir = __DIR__ . '/../Fixtures';

// Helper: load the reference JWKS as array
function loadJwks(): array
{
    return json_decode(file_get_contents(__DIR__ . '/../Fixtures/jwks.json'), true);
}

function loadExpectedPem(): string
{
    return file_get_contents(__DIR__ . '/../Fixtures/expected-pem.pem');
}

// ─── parseJwks + PEM encoding ─────────────────────────────────────────────────

it('parses JWKS and returns kid → PEM map via getPublicKey', function () use ($fixtureDir) {
    $jwks     = loadJwks();
    $expected = loadExpectedPem();

    Http::fake(['*' => Http::response($jwks, 200)]);

    $service   = app(JwksService::class);
    $publicKey = $service->getPublicKey('test-key-2026');

    expect($publicKey)->toBe($expected);
});

it('produces PEM byte-identical to openssl reference', function () use ($fixtureDir) {
    $jwks        = loadJwks();
    $expectedPem = loadExpectedPem();

    Http::fake(['*' => Http::response($jwks, 200)]);
    Cache::flush();

    $service   = app(JwksService::class);
    $publicKey = $service->getPublicKey('test-key-2026');

    expect($publicKey)->toBe($expectedPem);
});

it('filters out non-RSA and non-sig keys from JWKS', function () {
    $validKey = array_merge(loadJwks()['keys'][0], ['kid' => 'only-valid']);
    $jwks = [
        'keys' => [
            ['kty' => 'EC',  'use' => 'sig', 'kid' => 'ec-key'],
            ['kty' => 'RSA', 'use' => 'enc', 'kid' => 'rsa-enc', 'n' => $validKey['n'], 'e' => $validKey['e']],
            $validKey,
        ],
    ];

    // Only one call: cache miss → fetch → only-valid survives the filter
    Http::fake(['*' => Http::response($jwks, 200)]);
    Cache::flush();

    $service = app(JwksService::class);

    // EC and RSA-enc keys must not be exposed
    expect(fn () => $service->getPublicKey('ec-key'))->toThrow(RuntimeException::class);
    expect(fn () => $service->getPublicKey('rsa-enc'))->toThrow(RuntimeException::class);
    // The RSA-sig key must be resolvable
    expect($service->getPublicKey('only-valid'))->not->toBeNull();
});

it('rejects JWK with wrong alg field (not RS256)', function () {
    $jwks = loadJwks();
    $jwks['keys'][0]['alg'] = 'RS384';

    Http::fake(['*' => Http::response($jwks, 200)]);
    Cache::flush();

    $service = app(JwksService::class);

    expect(fn () => $service->getPublicKey('test-key-2026'))->toThrow(RuntimeException::class);
});

it('returns RSA sig key with explicit RS256 alg', function () {
    Http::fake(['*' => Http::response(loadJwks(), 200)]);
    Cache::flush();

    $service = app(JwksService::class);
    $key = $service->getPublicKey('test-key-2026');

    expect($key)->not->toBeNull();
});

// ─── Caching ──────────────────────────────────────────────────────────────────

it('caches JWKS in array store after first fetch', function () {
    Http::fake(['*' => Http::response(loadJwks(), 200)]);
    Cache::flush();

    $service = app(JwksService::class);
    $service->getPublicKey('test-key-2026');
    $service->getPublicKey('test-key-2026'); // second call should use cache

    Http::assertSentCount(1);
});

it('refetches JWKS when kid is not in cache', function () {
    // Prime cache with a JWKS that doesn't have our kid
    $otherJwks = ['keys' => [
        array_merge(loadJwks()['keys'][0], ['kid' => 'other-kid']),
    ]];

    Http::fake(['*' => Http::sequence()
        ->push($otherJwks, 200)
        ->push(loadJwks(), 200),
    ]);
    Cache::flush();

    $service = app(JwksService::class);
    $service->getPublicKey('test-key-2026'); // triggers: first fetch → not found → force refetch

    Http::assertSentCount(2);
});

it('logs warning and falls back to cache when forced refetch returns 500', function () {
    // Sequence: first fetch primes cache, forced refetch gets 500
    Http::fake(['*' => Http::sequence()
        ->push(loadJwks(), 200)
        ->push(null, 500),
    ]);
    Cache::flush();
    Log::spy();

    $service = app(JwksService::class);
    $service->getPublicKey('test-key-2026'); // primes cache

    // Requesting an unknown kid triggers: cache hit → not found → force refetch (500) → fallback to cache → kid not in cache → throw
    expect(fn () => $service->getPublicKey('missing-kid'))
        ->toThrow(RuntimeException::class, 'JWKS key not found for kid: missing-kid');

    Log::shouldHaveReceived('warning')
        ->once()
        ->withArgs(fn ($msg) => str_contains($msg, 'JWKS fetch failed'));
});

it('resolves from cache when JWKS endpoint is down (no HTTP call needed)', function () {
    // Sequence with a single valid response — if a second HTTP call were made the sequence would throw
    Http::fake(['*' => Http::sequence()
        ->push(loadJwks(), 200),
    ]);
    Cache::flush();

    $service = app(JwksService::class);
    $service->getPublicKey('test-key-2026'); // primes cache (1 HTTP call)

    // Second request resolves from cache — no HTTP call needed
    $key = $service->getPublicKey('test-key-2026');
    expect($key)->not->toBeNull();

    Http::assertSentCount(1);
});

it('throws when kid not found even after forced refetch', function () {
    Http::fake(['*' => Http::response(loadJwks(), 200)]);
    Cache::flush();

    $service = app(JwksService::class);

    expect(fn () => $service->getPublicKey('nonexistent-kid'))->toThrow(
        RuntimeException::class,
        'JWKS key not found for kid: nonexistent-kid'
    );
});
