<?php

namespace Maya\Auth\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Garantiza que `$request->user()` no sea null después de que `JwtMiddleware`
 * haya autenticado el token.
 *
 * Protege contra la race condition de primer login: el usuario existe en
 * Keycloak pero aún no ha sido sincronizado en la tabla local `users`. Sin
 * este middleware, el controller recibiría `null` del guard y podría lanzar
 * una excepción no controlada o procesar la request con identidad vacía.
 *
 * Debe colocarse en la pila DESPUÉS de `JwtMiddleware` (o del alias `jwt`):
 *
 *     ->middleware(['jwt', 'requires-local-user'])
 *
 * El middleware devuelve 401 (no 403) porque el problema es de identidad
 * (el usuario no está provisionado), no de permisos.
 */
class RequiresLocalUserMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        if ($request->user() === null) {
            return response()->json([
                'message' => 'User not provisioned in local database.',
                'code'    => 'USER_NOT_PROVISIONED',
            ], 401);
        }

        return $next($request);
    }
}
