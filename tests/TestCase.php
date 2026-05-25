<?php

namespace Tests;

use Maya\Auth\Providers\SharedAuthServiceProvider;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

abstract class TestCase extends OrchestraTestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            SharedAuthServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('auth.jwks_url', 'http://keycloak.test/realms/maya/protocol/openid-connect/certs');
        $app['config']->set('auth.jwt_issuer', 'https://keycloak.maya.test/realms/maya');
        $app['config']->set('auth.jwt_audience', 'maya-test-service');
        $app['config']->set('auth.jwks_cache_ttl', 3600);
        $app['config']->set('auth.dev_bypass_auth', false);
        $app['config']->set('cache.default', 'array');
    }
}
