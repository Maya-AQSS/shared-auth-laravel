# ceedcv-maya/shared-auth-laravel

Keycloak/OIDC JWT authentication middleware for Laravel: JWKS caching, RequirePermissionMiddleware, AppToAppAuthenticator, configurable user resolver.

Part of the [ceedcv-maya/maya_platform](https://github.com/Maya-AQSS/maya_platform) mono-repo. Distributed independently for reuse outside the Maya ecosystem.

## Installation

```bash
composer require ceedcv-maya/shared-auth-laravel
```

```php
// routes/api.php
use Maya\Auth\Middleware\AuthenticateJwt;
use Maya\Auth\Middleware\RequirePermission;

Route::middleware([AuthenticateJwt::class, RequirePermission::class.':users.read'])->group(function () {
    Route::get('/me', fn () => auth()->user());
});
```

```env
KEYCLOAK_URL=https://keycloak.example.org
KEYCLOAK_REALM=my-realm
KEYCLOAK_CLIENT_ID=my-app
```


## TypeScript / build notes
PSR-4 autoload from `src/`. Service providers are registered via Laravel package discovery (no manual provider registration needed).

## License

MIT — see [LICENSE](LICENSE).

## Reporting issues

The canonical source lives in [Maya-AQSS/maya_platform](https://github.com/Maya-AQSS/maya_platform). File issues there; this read-only split repo is only the published artifact.
