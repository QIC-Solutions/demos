// Piloto post-cuántico: el intercambio de la clave del monedero se hace con
// ML-KEM-768 y los recibos se firman con ML-DSA-65 (@noble/post-quantum).
import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';

export function encapsularMonedero(publicaMonedero: Uint8Array) {
  return ml_kem768.encapsulate(publicaMonedero);
}

export function firmarRecibo(recibo: Uint8Array) {
  const claves = ml_dsa65.keygen();
  return ml_dsa65.sign(claves.secretKey, recibo);
}
