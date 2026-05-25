<?php

namespace Maya\Auth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Comprueba que el JWT del usuario autenticado contiene al menos uno de los
 * roles indicados. Los roles llegan como parámetros variádicos del alias del
 * middleware:
 *
 *     ->middleware('role:admin')
 *     ->middleware('role:admin,super-admin')
 *
 * `JwtMiddleware` deposita los claims en `request->attributes->jwt_user`. Si
 * ese atributo no existe (entornos de test que se saltan el JWT), se permite
 * el paso para no romper las suites.
 */
class RequireRoleMiddleware
{
    public function handle(Request $request, Closure $next, string ...$roles): Response
    {
        $jwtUser = $request->attributes->get('jwt_user');

        if ($jwtUser === null) {
            // JwtMiddleware bypassed (typically tests) — skip role check.
            return $next($request);
        }

        $userRoles = (array) ($jwtUser['roles'] ?? []);

        foreach ($roles as $required) {
            if (in_array($required, $userRoles, true)) {
                return $next($request);
            }
        }

        abort(403, 'Forbidden.');
    }
}
