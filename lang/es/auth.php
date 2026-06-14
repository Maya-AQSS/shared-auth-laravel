<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Auth — mensajes de cara al cliente (401/403)
    |--------------------------------------------------------------------------
    |
    | Catálogo del paquete shared-auth-laravel. Registrado bajo el namespace
    | 'shared-auth' en SharedAuthServiceProvider. Las apps consumidoras pueden
    | sobreescribir estas claves publicando lang/vendor/shared-auth.
    |
    | es = idioma canónico. en/va mantienen paridad total de claves.
    |
    */

    'unauthenticated' => 'No autenticado.',

    'forbidden' => 'No tienes permiso para realizar esta acción.',

    'user_not_found_or_inactive' => 'Empleado no encontrado o inactivo.',

    'user_not_provisioned' => 'El usuario no está dado de alta en la base de datos local.',
];
