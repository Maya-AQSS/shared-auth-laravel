<?php

namespace Maya\Auth\Contracts;

interface JwksServiceInterface
{
    /**
     * Devuelve la clave pública RSA en formato PEM correspondiente al kid.
     */
    public function getPublicKey(string $kid): string;

    /**
     * Invalida la caché local de JWKS. Llamar tras una rotación de claves en Keycloak.
     */
    public function invalidateCache(): void;
}
