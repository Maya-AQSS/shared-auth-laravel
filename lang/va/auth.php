<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Auth — missatges de cara al client (401/403)
    |--------------------------------------------------------------------------
    |
    | Catàleg del paquet shared-auth-laravel. Registrat sota el namespace
    | 'shared-auth' en SharedAuthServiceProvider. Les apps consumidores poden
    | sobreescriure estes claus publicant lang/vendor/shared-auth.
    |
    | es = idioma canònic. en/va mantenen paritat total de claus.
    |
    */

    'unauthenticated' => 'No autenticat.',

    'forbidden' => 'No tens permís per a realitzar esta acció.',

    'user_not_found_or_inactive' => 'Empleat no trobat o inactiu.',

    'user_not_provisioned' => "L'usuari no està donat d'alta en la base de dades local.",
];
