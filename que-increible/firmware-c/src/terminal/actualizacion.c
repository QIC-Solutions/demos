/*
 * Actualizaciones del firmware por el aire (2026): el paquete se firma con
 * ML-DSA-65 y la clave de sesión con la central se encapsula con ML-KEM-768
 * (liboqs). Lo que había antes, firma ECDSA, se mantiene para los TPV viejos.
 */
#include <oqs/oqs.h>

OQS_SIG *verificador_actualizaciones(void)
{
    return OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
}

OQS_KEM *kem_sesion(void)
{
    return OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
}
