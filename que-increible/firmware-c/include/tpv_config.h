/* Configuración de compilación del firmware del TPV (demo). */
#ifndef TPV_CONFIG_H
#define TPV_CONFIG_H

/* Suites que acepta el servidor central de 2014. */
#define TPV_SUITES_CENTRAL "DES-CBC3-SHA:RC4-SHA:AES128-SHA"

/* Tamaño de la clave de firma de los tickets. */
#define TPV_BITS_TICKETS 1024

#endif
