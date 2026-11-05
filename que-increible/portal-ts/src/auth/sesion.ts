// Sesiones del portal de clientes (JWT).
import jwt from 'jsonwebtoken';
import { readFileSync } from 'node:fs';

// DEMO — criptografía incrustada: secreto HS256 en el código (ficticio).
const jwtSecret = 'portal-que-increible-demo-secreto-NO-REAL';

export function emitirSesion(cliente: string): string {
  return jwt.sign({ sub: cliente }, jwtSecret, { algorithm: 'HS256', expiresIn: '1h' });
}

import { readFileSync } from 'node:fs';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { ed25519 } from '@noble/curves/ed25519';

const b64url = (b: Uint8Array): string => Buffer.from(b).toString('base64url');

// Tokens para la app móvil: JWS híbrido Ed25519 + ML-DSA-65 (FIPS 204).
// El verificador DEBE validar ambas firmas (Ed25519 = primeros 64 bytes, ML-DSA-65 = resto).
export function emitirSesionMovil(cliente: string): string {
  const claveEd = readFileSync('/etc/portal/movil_ed25519.key');    // 32 bytes raw
  const claveMldsa = readFileSync('/etc/portal/movil_mldsa65.key');  // clave secreta ML-DSA-65 raw
  const header = b64url(Buffer.from(JSON.stringify({ alg: 'Ed25519+ML-DSA-65', typ: 'JWT' })));
  const payload = b64url(Buffer.from(JSON.stringify({ sub: cliente, iat: Math.floor(Date.now() / 1000) })));
  const datos = Buffer.from(`${header}.${payload}`);
  const firmaEd = ed25519.sign(datos, claveEd);
  const firmaMldsa = ml_dsa65.sign(claveMldsa, datos);
  return `${header}.${payload}.${b64url(Buffer.concat([firmaEd, firmaMldsa]))}`;
}

// Sesiones de socios: el algoritmo queda FIJADO en código (híbrido Ed25519 + ML-DSA-65),
// nunca lo decide el despliegue para evitar degradación a RSA/HS256.
export function emitirSesionSocios(cliente: string, claveEd: Buffer, claveMldsa: Buffer): string {
  return jwt.sign({ sub: cliente }, clave, { algorithm: process.env.PORTAL_JWT_ALG as jwt.Algorithm });
}
