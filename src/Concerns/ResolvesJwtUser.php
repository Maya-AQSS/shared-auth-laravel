<?php

declare(strict_types=1);

namespace Maya\Auth\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Maya\Auth\Support\JwtSubject;

/**
 * Generalised trait that translates the JWT subject extracted by JwtMiddleware
 * into an Eloquent model lookup.
 *
 * Usage:
 *
 *   class MyController extends Controller
 *   {
 *       use ResolvesJwtUser;
 *
 *       // Optional: override the default \App\Models\User class.
 *       protected function jwtUserModel(): string
 *       {
 *           return \App\Models\StaffMember::class;
 *       }
 *   }
 *
 * The host model MUST use `id` as its primary key, with `$incrementing = false`
 * and `$keyType = 'string'` because the JWT subject is always a UUID string.
 *
 * Derived from the `ResolvesJwtUser` trait in maya_logs but generalised to:
 *  - Use JwtSubject (shared-auth) instead of inline attribute extraction.
 *  - Support configurable model via `jwtUserModel()` instead of hard-coding User.
 *  - Not include the `resolveJwtUserOrFail` helper (which throws app-specific
 *    exceptions) — callers can add their own abort/throw on top of `resolveJwtUser`.
 */
trait ResolvesJwtUser
{
    /**
     * Returns the Eloquent model matching the JWT subject, or null when:
     *  - The `jwt_user` attribute is missing or malformed.
     *  - No record exists for the extracted id.
     *
     * @return Model|null
     */
    protected function resolveJwtUser(Request $request): ?Model
    {
        $id = JwtSubject::fromRequest($request);

        if ($id === null) {
            return null;
        }

        /** @var class-string<Model> $modelClass */
        $modelClass = $this->jwtUserModel();

        return $modelClass::find($id);
    }

    /**
     * Returns the fully-qualified class name of the Eloquent model to look up.
     *
     * Override in the host class to use a model other than App\Models\User.
     *
     * @return class-string<Model>
     */
    protected function jwtUserModel(): string
    {
        return \App\Models\User::class;
    }
}
