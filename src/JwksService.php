<?php

namespace Maya\Auth;

use Maya\Auth\Contracts\JwksServiceInterface;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Math\BigInteger;
use RuntimeException;

class JwksService implements JwksServiceInterface
{
    private const CACHE_KEY = 'jwks_keys';

    private function cacheTtl(): int
    {
        return (int) config('auth.jwks_cache_ttl', 3600);
    }

    /**
     * Removes the JWKS cache entry so the next call to getPublicKey() re-fetches
     * from Keycloak. Use this after a key rotation event.
     */
    public function invalidateCache(): void
    {
        Cache::forget(self::CACHE_KEY);
    }

    /**
     * Devuelve la clave pública RSA correspondiente al kid del token.
     * Primero busca en caché Redis; si no existe o ha expirado, descarga del JWKS.
     * Si el endpoint JWKS no responde, usa las claves cacheadas como fallback (Zero Trust).
     */
    public function getPublicKey(string $kid): string
    {
        $keys = $this->getCachedKeys() ?? $this->fetchAndCacheKeys();

        if (! isset($keys[$kid])) {
            // Kid no encontrado en caché — refrescar una vez
            $keys = $this->fetchAndCacheKeys(force: true);
        }

        if (! isset($keys[$kid])) {
            throw new RuntimeException("JWKS key not found for kid: {$kid}");
        }

        return $keys[$kid];
    }

    private function getCachedKeys(): ?array
    {
        return Cache::get(self::CACHE_KEY);
    }

    private function fetchAndCacheKeys(bool $force = false): array
    {
        if (! $force) {
            $cached = $this->getCachedKeys();
            if ($cached !== null) {
                return $cached;
            }
        }

        $jwksUrl = config('auth.jwks_url');

        try {
            $response = Http::timeout(5)->get($jwksUrl);

            if (! $response->successful()) {
                throw new RuntimeException("JWKS endpoint returned {$response->status()}");
            }

            $keys = $this->parseJwks($response->json());
            Cache::put(self::CACHE_KEY, $keys, $this->cacheTtl());

            return $keys;
        } catch (\Exception $e) {
            Log::warning('JWKS fetch failed, using cached keys (Zero Trust fallback)', [
                'error' => $e->getMessage(),
                'url'   => $jwksUrl,
            ]);

            $cached = $this->getCachedKeys();

            if ($cached === null) {
                throw new RuntimeException('JWKS unavailable and no cached keys found: ' . $e->getMessage());
            }

            return $cached;
        }
    }

    /**
     * Convierte el array JWKS en un mapa kid → PEM.
     */
    private function parseJwks(array $jwks): array
    {
        $keys = [];

        foreach ($jwks['keys'] ?? [] as $key) {
            if (($key['kty'] ?? '') !== 'RSA' || ($key['use'] ?? '') !== 'sig') {
                continue;
            }

            if (isset($key['alg']) && $key['alg'] !== 'RS256') {
                continue;
            }

            $kid = $key['kid'];
            $pem = $this->rsaJwkToPem($key);

            if ($pem !== null) {
                $keys[$kid] = $pem;
            }
        }

        return $keys;
    }

    private function rsaJwkToPem(array $jwk): ?string
    {
        if (empty($jwk['n']) || empty($jwk['e'])) {
            return null;
        }

        try {
            $key = PublicKeyLoader::load([
                'n' => new BigInteger($this->base64UrlDecode($jwk['n']), 256),
                'e' => new BigInteger($this->base64UrlDecode($jwk['e']), 256),
            ]);

            // phpseclib3 emits CRLF without trailing newline; normalize to LF + trailing newline
            $pem = str_replace("\r\n", "\n", $key->toString('PKCS8'));

            return str_ends_with($pem, "\n") ? $pem : $pem . "\n";
        } catch (\Throwable) {
            return null;
        }
    }

    private function base64UrlDecode(string $data): string
    {
        $padded = str_pad(strtr($data, '-_', '+/'), strlen($data) + (4 - strlen($data) % 4) % 4, '=');

        return base64_decode($padded);
    }
}
