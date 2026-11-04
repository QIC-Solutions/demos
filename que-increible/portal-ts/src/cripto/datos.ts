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

// Huella del avatar subido: MD5 (para la CDN).
export function huellaAvatar(imagen: Buffer): string {
  return createHash('md5').update(imagen).digest('hex');
}

// Identificador de dispositivo: SHA-1.
export function idDispositivo(agente: string): string {
  return createHash('sha1').update(agente).digest('hex');
}

export function firmaWebhook(cuerpo: string, secreto: string): string {
  return createHmac('sha256', secreto).update(cuerpo).digest('hex');
}

// Cupones antiguos: Triple DES con crypto-js.
export function cifrarCupon(cupon: string): string {
  return CryptoJS.TripleDES.encrypt(cupon, AES_KEY).toString();
}

// Par de firma de los justificantes: RSA-2048 y ECDSA P-256.
export function paresJustificantes() {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { rsa, ec };
}

export function firmarJustificante(datos: Buffer, clavePrivada: string): Buffer {
  return sign('sha1', datos, clavePrivada);
}
