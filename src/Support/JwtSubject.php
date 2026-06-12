<?php

declare(strict_types=1);

namespace Maya\Auth\Support;

use Illuminate\Http\Request;

/**
 * Static helpers to extract identity information from the `jwt_user` request
 * attribute deposited by JwtMiddleware.
 *
 * Having these as a plain static class (rather than a trait) allows both
 * controllers and FormRequests to share the extraction logic without
 * inheritance constraints.
 */
final class JwtSubject
{
    /**
     * Returns the non-empty string id of the authenticated JWT subject, or null.
     *
     * Rules:
     *  - The `jwt_user` request attribute must be a non-null array.
     *  - The array must contain an `id` key whose value is a non-empty string.
     *  - Any other shape (missing attribute, null, non-array, integer id, …) returns null.
     */
    public static function fromRequest(Request $request): ?string
    {
        $jwtUser = $request->attributes->get('jwt_user');

        if (! is_array($jwtUser)) {
            return null;
        }

        $id = $jwtUser['id'] ?? null;

        return is_string($id) && $id !== '' ? $id : null;
    }

    /**
     * Returns the full claims array stored in `jwt_user`, or an empty array
     * when the attribute is absent, null, or not an array.
     *
     * @return array<string, mixed>
     */
    public static function claims(Request $request): array
    {
        $jwtUser = $request->attributes->get('jwt_user');

        return is_array($jwtUser) ? $jwtUser : [];
    }
}
