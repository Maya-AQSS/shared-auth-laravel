<?php

namespace Maya\Auth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Maya\Auth\Http\AuthErrorResponse;
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
 * ese atributo no existe, la petición se rechaza (fail closed): JwtMiddleware
 * debe ejecutarse antes; los tests inyectan un `jwt_user` falso en vez de
 * depender de un bypass.
 */
class RequireRoleMiddleware
{
    public function handle(Request $request, Closure $next, string ...$roles): Response
    {
        $jwtUser = $request->attributes->get('jwt_user');

        if ($jwtUser === null) {
            // Fail closed: never pass through a role-gated route without an
            // authenticated JWT user.
            return AuthErrorResponse::unauthenticated();
        }

        $userRoles = (array) ($jwtUser['roles'] ?? []);

        foreach ($roles as $required) {
            if (in_array($required, $userRoles, true)) {
                return $next($request);
            }
        }

        return AuthErrorResponse::forbidden();
    }
}
