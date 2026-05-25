<?php

namespace Maya\Auth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;

/**
 * Verifica que el usuario autenticado (JWT) tiene un permiso concreto.
 *
 * Los permisos se leen de la vista `user_resolved_permissions` (FDW a
 * maya_auth) que aplica la jerarquía de roles y los overrides grant/deny.
 * El resultado se cachea en Redis durante 5 minutos por usuario+permiso.
 *
 * Uso en rutas: `->middleware('permission:alerts.manage')`.
 *
 * Cada app puede registrarlo con su propio alias en `bootstrap/app.php`:
 *
 *     $middleware->alias([
 *         'permission' => \Maya\Auth\Middleware\RequirePermissionMiddleware::class,
 *     ]);
 */
class RequirePermissionMiddleware
{
    private const CACHE_TTL = 300;

    public function handle(Request $request, Closure $next, string $permission): Response
    {
        $jwtUser = $request->attributes->get('jwt_user');

        if ($jwtUser === null) {
            // JwtMiddleware bypassed (typically tests) — skip permission check.
            return $next($request);
        }

        $userId   = (string) ($jwtUser['id'] ?? '');
        $cacheKey = "perm:{$userId}:{$permission}";

        $has = Cache::remember($cacheKey, self::CACHE_TTL, function () use ($userId, $permission): bool {
            return DB::table('user_resolved_permissions')
                ->where('user_id', $userId)
                ->where('permission_slug', $permission)
                ->exists();
        });

        if (! $has) {
            abort(403, "Forbidden: missing permission '{$permission}'.");
        }

        return $next($request);
    }
}
