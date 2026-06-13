<?php

namespace Maya\Auth\Providers;

use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Maya\Auth\Contracts\JwksServiceInterface;
use Maya\Auth\JwksService;
use Maya\Auth\Middleware\RequiresLocalUserMiddleware;
use RuntimeException;

class SharedAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(JwksServiceInterface::class, JwksService::class);
    }

    public function boot(): void
    {
        // ... here we could publish configs if we extract them, but for now we expect the app to provide config('auth.jwks_url')

        // Defensa en profundidad: aunque JwtMiddleware ya ignora el bypass fuera de
        // 'local', abortamos el arranque si DEV_BYPASS_AUTH=true se cuela en otro
        // entorno — convierte un misconfig latente en un error inmediato.
        self::assertDevBypassAuthSafe(
            $this->app->environment(),
            (bool) config('auth.dev_bypass_auth', false),
        );

        /** @var Router $router */
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('requires-local-user', RequiresLocalUserMiddleware::class);
    }

    /**
     * @throws RuntimeException si DEV_BYPASS_AUTH está activo fuera del entorno 'local'.
     */
    public static function assertDevBypassAuthSafe(string $environment, bool $devBypassAuth): void
    {
        if ($devBypassAuth && $environment !== 'local') {
            throw new RuntimeException(
                "DEV_BYPASS_AUTH=true no está permitido fuera del entorno 'local' "
                ."(actual: '{$environment}'). Desactívalo en la configuración de este entorno."
            );
        }
    }
}
