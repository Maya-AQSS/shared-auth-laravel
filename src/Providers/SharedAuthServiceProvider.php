<?php

namespace Maya\Auth\Providers;

use Illuminate\Support\ServiceProvider;
use Maya\Auth\Contracts\JwksServiceInterface;
use Maya\Auth\JwksService;

class SharedAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(JwksServiceInterface::class, JwksService::class);
    }

    public function boot(): void
    {
        // ... here we could publish configs if we extract them, but for now we expect the app to provide config('auth.jwks_url')
    }
}
