<?php

namespace Maya\Auth\Http;

use Illuminate\Http\JsonResponse;

/**
 * Centralized factory for authentication/authorization error responses.
 * All services in the Maya ecosystem should use these helpers to ensure
 * consistent error envelopes across microservices.
 */
class AuthErrorResponse
{
    /**
     * 401 Unauthenticated — missing or invalid token.
     */
    public static function unauthenticated(string $error = 'invalid_token'): JsonResponse
    {
        return response()->json(
            ['error' => 'Unauthenticated'],
            401,
            ['WWW-Authenticate' => sprintf('Bearer realm="api", error="%s"', $error)],
        );
    }

    /**
     * 401 Unauthenticated — no Authorization header present.
     */
    public static function missingToken(): JsonResponse
    {
        return response()->json(
            ['error' => 'Unauthenticated'],
            401,
            ['WWW-Authenticate' => 'Bearer realm="api"'],
        );
    }

    /**
     * 403 Forbidden — authenticated but lacking required role/permission.
     */
    public static function forbidden(string $message = 'Forbidden'): JsonResponse
    {
        return response()->json(['error' => $message], 403);
    }
}
