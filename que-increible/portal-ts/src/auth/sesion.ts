// Sesiones del portal de clientes (JWT).
import jwt from 'jsonwebtoken';
import { readFileSync } from 'node:fs';

// DEMO — criptografía incrustada: secreto HS256 en el código (ficticio).
const jwtSecret = 'portal-que-increible-demo-secreto-NO-REAL';

export function emitirSesion(cliente: string): string {
  return jwt.sign({ sub: cliente }, jwtSecret, { algorithm: 'HS256', expiresIn: '1h' });
}

// Tokens para la app móvil: RS256 con la clave del portal.
export function emitirSesionMovil(cliente: string): string {
  const clave = readFileSync('/etc/portal/movil.key');
  return jwt.sign({ sub: cliente }, clave, { algorithm: 'RS256' });
}

// La alternativa ágil: el algoritmo lo fija el despliegue.
export function emitirSesionSocios(cliente: string, clave: Buffer): string {
  return jwt.sign({ sub: cliente }, clave, { algorithm: process.env.PORTAL_JWT_ALG as jwt.Algorithm });
}
