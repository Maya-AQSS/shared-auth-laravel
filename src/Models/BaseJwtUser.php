<?php

namespace Maya\Auth\Models;

use Illuminate\Contracts\Auth\Access\Authorizable as AuthorizableContract;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Auth\Access\Authorizable;

/**
 * DTO base que representa al usuario autenticado a partir de los claims JWT.
 *
 * No es un modelo Eloquent — no hay tabla 'jwt_users'. Se construye en
 * {@see \Maya\Auth\Middleware\JwtMiddleware} y se inyecta en el auth guard.
 *
 * Las apps con scope académico u otros campos custom deben extender esta clase
 * (`class JwtUser extends \Maya\Auth\Models\BaseJwtUser`) y agregar las propiedades
 * adicionales en su propio constructor (llamando a `parent::__construct($claims)`).
 */
class BaseJwtUser implements Authenticatable, AuthorizableContract
{
    use Authorizable;

    public readonly string $id;

    public readonly ?string $email;

    public readonly ?string $name;

    public readonly ?string $department;

    /**
     * Códigos de permiso desde BD (`user_permissions`), resueltos en el guard.
     *
     * @var list<string>
     */
    public readonly array $permissions;

    public readonly string $scope;

    public function __construct(array $claims)
    {
        $this->id = $claims['id'];
        $this->email = $claims['email'] ?? null;
        $this->name = $claims['name'] ?? null;
        $this->department = $claims['department'] ?? $claims['departamento'] ?? null;
        $this->permissions = array_values(array_unique(array_map(
            static fn ($c): string => (string) $c,
            $claims['permissions'] ?? [],
        )));
        $this->scope = $claims['scope'] ?? '';
    }

    /**
     * Comprueba si el usuario tiene un permiso concedido en BD.
     */
    public function hasPermission(string $code): bool
    {
        return in_array($code, $this->permissions, strict: true);
    }

    /**
     * Normaliza lista + valor escalar de claims (arrays o JSON en string).
     * Útil para campos como `study_type_ids` que pueden llegar como list o scalar.
     *
     * @return list<string>
     */
    public static function mergeScopeIds(mixed $listClaim, mixed $scalarClaim): array
    {
        $out = [];

        if (is_string($listClaim) && $listClaim !== '') {
            $decoded = json_decode($listClaim, true);
            $listClaim = is_array($decoded) ? $decoded : null;
        }

        if (is_array($listClaim)) {
            foreach ($listClaim as $v) {
                if ($v !== null && $v !== '') {
                    $out[] = (string) $v;
                }
            }
        }

        if (is_string($scalarClaim) && $scalarClaim !== '') {
            $out[] = $scalarClaim;
        }

        return array_values(array_unique($out));
    }

    // ── Authenticatable contract ──────────────────────────────

    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    public function getAuthIdentifier(): string
    {
        return $this->id;
    }

    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    public function getAuthPassword(): string
    {
        return '';
    }

    public function getRememberToken(): string
    {
        return '';
    }

    public function setRememberToken($value): void {}

    public function getRememberTokenName(): string
    {
        return '';
    }
}
