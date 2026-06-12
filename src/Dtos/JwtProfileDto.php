<?php

declare(strict_types=1);

namespace Maya\Auth\Dtos;

use Illuminate\Http\Request;

/**
 * Minimal, immutable representation of the JWT profile extracted from the
 * `jwt_user` request attribute deposited by JwtMiddleware.
 *
 * Design decisions:
 *  - NOT final — host apps or other shared packages may extend it and add
 *    typed accessors over specific claim keys (e.g. academic context in DMS).
 *  - `$claims` carries the raw attribute array so that all extra claims are
 *    accessible without requiring a subclass.  Subclasses can expose them as
 *    typed getters without needing to change the base constructor.
 *  - The academic-specific typed properties found in the DMS copy of this DTO
 *    are intentionally excluded here; consumers should read them from `$claims`
 *    or build a domain-specific subclass.
 */
readonly class JwtProfileDto
{
    /**
     * @param array<string, mixed> $claims Full raw claims array (includes `id` and every other claim).
     */
    public function __construct(
        public string $id,
        public array $claims = [],
    ) {}

    /**
     * Build a DTO from a raw claims array (typically the value of `jwt_user`).
     *
     * Returns null when `id` is missing, empty, or not a string.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): ?self
    {
        $id = $data['id'] ?? null;

        if (! is_string($id) || $id === '') {
            return null;
        }

        return new self(id: $id, claims: $data);
    }

    /**
     * Build a DTO from the `jwt_user` request attribute set by JwtMiddleware.
     *
     * Returns null when the attribute is absent, null, not an array, or has an
     * invalid/empty `id`.
     */
    public static function fromRequestAttribute(Request $request): ?self
    {
        $jwtUser = $request->attributes->get('jwt_user');

        if (! is_array($jwtUser)) {
            return null;
        }

        return self::fromArray($jwtUser);
    }
}
