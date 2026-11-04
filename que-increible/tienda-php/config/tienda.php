<?php
// Configuración de la tienda (demo). El cifrado de los carritos guardados se
// elige aquí, no en el código.
return [
    'cifrado_carrito' => getenv('TIENDA_CIFRADO') ?: 'aes-256-gcm',
    'url_pasarela' => 'https://pagos.que-increible.example/api',
];
