<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Auth — client-facing messages (401/403)
    |--------------------------------------------------------------------------
    |
    | Catalog for the shared-auth-laravel package. Registered under the
    | 'shared-auth' namespace in SharedAuthServiceProvider. Consumer apps may
    | override these keys by publishing lang/vendor/shared-auth.
    |
    | es is the canonical language. en/va keep full key parity.
    |
    */

    'unauthenticated' => 'Unauthenticated.',

    'forbidden' => 'You are not allowed to perform this action.',

    'user_not_found_or_inactive' => 'Employee not found or inactive.',

    'user_not_provisioned' => 'User is not provisioned in the local database.',
];
