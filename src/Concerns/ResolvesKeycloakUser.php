<?php

namespace Maya\Auth\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

/**
 * Resolve the Eloquent User matching the JWT's `sub` claim against the FDW view.
 *
 * The view is read-only (postgres_fdw → odoo.v_app_users). No auto-provisioning:
 * if the employee is not in Odoo or not yet synced to Keycloak, the request is
 * rejected with 403.
 *
 * The host app must declare:
 *   protected string $keycloakUserModel = \App\Models\User::class;
 *
 * The bound model must use `id` (varchar) as primary key and have `$incrementing = false`.
 */
trait ResolvesKeycloakUser
{
    /** Override per host app or configure via config('auth.keycloak_user_model'). */
    protected ?string $keycloakUserModel = null;

    protected function resolveKeycloakUser(Request $request): Model
    {
        $jwtUser = $request->attributes->get('jwt_user');
        $sub     = $jwtUser['id'] ?? $jwtUser['sub'] ?? null;

        abort_if($sub === null, 401, 'Unauthenticated');

        /** @var class-string<Model> $modelClass */
        $modelClass = $this->keycloakUserModel
            ?? config('auth.keycloak_user_model', \App\Models\User::class);
        $user       = $modelClass::query()->where('id', $sub)->first();

        abort_if($user === null, 403, 'Empleado no encontrado o inactivo en Odoo');

        return $user;
    }
}
