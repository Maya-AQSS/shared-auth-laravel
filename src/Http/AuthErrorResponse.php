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
            ['error' => __('shared-auth::auth.unauthenticated')],
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
            ['error' => __('shared-auth::auth.unauthenticated')],
            401,
            ['WWW-Authenticate' => 'Bearer realm="api"'],
        );
    }

    /**
     * 403 Forbidden — authenticated but lacking required role/permission.
     *
     * The caller may override the message; when omitted, the localized default
     * from the 'shared-auth' translation namespace is used.
     */
    public static function forbidden(?string $message = null): JsonResponse
    {
        return response()->json(
            ['error' => $message ?? __('shared-auth::auth.forbidden')],
            403,
        );
    }
}
