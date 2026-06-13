<?php

use Maya\Auth\Providers\SharedAuthServiceProvider;

// ─── DEV_BYPASS_AUTH boot guard (M-03) ──────────────────────────────────────

it('permite el bypass en entorno local', function () {
    SharedAuthServiceProvider::assertDevBypassAuthSafe('local', true);
})->throwsNoExceptions();

it('no exige nada cuando el bypass está desactivado fuera de local', function () {
    SharedAuthServiceProvider::assertDevBypassAuthSafe('production', false);
    SharedAuthServiceProvider::assertDevBypassAuthSafe('testing', false);
    SharedAuthServiceProvider::assertDevBypassAuthSafe('staging', false);
})->throwsNoExceptions();

it('aborta si el bypass está activo en production', function () {
    SharedAuthServiceProvider::assertDevBypassAuthSafe('production', true);
})->throws(RuntimeException::class, 'DEV_BYPASS_AUTH=true');

it('aborta si el bypass está activo en staging', function () {
    SharedAuthServiceProvider::assertDevBypassAuthSafe('staging', true);
})->throws(RuntimeException::class, "(actual: 'staging')");

it('aborta si el bypass está activo en testing', function () {
    SharedAuthServiceProvider::assertDevBypassAuthSafe('testing', true);
})->throws(RuntimeException::class);

it('no rompe el arranque normal del provider (testing, sin bypass)', function () {
    // El boot ya corrió en el bootstrap de Testbench con dev_bypass_auth=false.
    expect(config('auth.dev_bypass_auth'))->toBeFalse();
});
