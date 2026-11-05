// Cifrado de las preferencias y del historial del cliente.
import { createCipheriv, createHash, createHmac, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import CryptoJS from 'crypto-js';

// DEMO: clave AES en el código (ficticia).
const AES_KEY = 'UG9ydGFsUXVlSW5jcmVpYmxlRGVtbzEy';

// Preferencias: versión de 2017, AES-128 en ECB.
export function cifrarPreferencias(json: string): Buffer {
  const cifrador = createCipheriv('aes-128-ecb', Buffer.from(AES_KEY, 'base64').subarray(0, 16), null);
  return Buffer.concat([cifrador.update(json, 'utf8'), cifrador.final()]);
}

// Historial: AES-256-GCM.
export function cifrarHistorial(texto: string, clave: Buffer): Buffer {
  const iv = randomBytes(12);
  const cifrador = createCipheriv('aes-256-gcm', clave, iv);
  return Buffer.concat([iv, cifrador.update(texto, 'utf8'), cifrador.final(), cifrador.getAuthTag()]);
}

// Huella del avatar subido: SHA-256 (para la CDN).
// Migrado desde MD5 (roto frente a colisiones). Salida: 64 caracteres hex.
export function huellaAvatar(imagen: Buffer): string {
  return createHash('sha256').update(imagen).digest('hex');
}

// Identificador de dispositivo: SHA-1.
// TODO: SHA-1 también está deprecado (colisiones); migrar a SHA-256 en un hallazgo aparte.
export function idDispositivo(agente: string): string {
  return createHash('sha1').update(agente).digest('hex');
}

export function firmaWebhook(cuerpo: string, secreto: string): string {
  return createHmac('sha256', secreto).update(cuerpo).digest('hex');
}

// Cupones: AES-256-GCM con el módulo nativo crypto de Node.js (crypto-js no soporta GCM).
// (mover el import al inicio del fichero)
import { randomBytes, createCipheriv } from "crypto";

export function cifrarCupon(cupon: string): string {
  const iv = randomBytes(12); // nonce de 96 bits, único por cada cifrado
  const cipher = createCipheriv("aes-256-gcm", AES_KEY_256, iv); // AES_KEY_256: Buffer de 32 bytes (256 bits)
  const cifrado = Buffer.concat([cipher.update(cupon, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Formato de salida: iv.tag.cifrado en base64
  return [iv, tag, cifrado].map((b) => b.toString("base64")).join(".");
import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import { x25519 } from '@noble/curves/ed25519';
import { hkdfSync, randomBytes } from 'crypto';

}

// Par de claves de los justificantes: híbrido X25519 + ML-KEM-768 (FIPS 203) en lugar de RSA-2048 / ECDSA P-256.
// NOTA: ML-KEM solo encapsula secretos; si los justificantes se FIRMAN, usar ML-DSA (FIPS 204).
export function paresJustificantes() {
  const mlkem = ml_kem768.keygen(randomBytes(64));
  const x25519Priv = x25519.utils.randomPrivateKey();
  const x25519Pub = x25519.getPublicKey(x25519Priv);
  return {
    mlkem: { publicKey: mlkem.publicKey, secretKey: mlkem.secretKey },
    x25519: { publicKey: x25519Pub, secretKey: x25519Priv },
  };
}

// Encapsulación híbrida: el secreto final deriva de X25519 y ML-KEM-768 vía HKDF.
export function encapsularHibrido(pubMlkem: Uint8Array, pubX25519: Uint8Array) {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(pubMlkem);
  const ephPriv = x25519.utils.randomPrivateKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const ssX = x25519.getSharedSecret(ephPriv, pubX25519);
  const clave = hkdfSync('sha256', Buffer.concat([Buffer.from(ssX), Buffer.from(sharedSecret)]), 'justificantes-v2', 'X25519+ML-KEM-768', 32);
  return { cipherText, ephPub, clave: Buffer.from(clave) };
}

export function desencapsularHibrido(cipherText: Uint8Array, ephPub: Uint8Array, secMlkem: Uint8Array, secX25519: Uint8Array) {
  const ssK = ml_kem768.decapsulate(cipherText, secMlkem);
  const ssX = x25519.getSharedSecret(secX25519, ephPub);
  return Buffer.from(hkdfSync('sha256', Buffer.concat([Buffer.from(ssX), Buffer.from(ssK)]), 'justificantes-v2', 'X25519+ML-KEM-768', 32));
}

export function firmarJustificante(datos: Buffer, clavePrivada: string): Buffer {
  return sign('sha1', datos, clavePrivada);
}
