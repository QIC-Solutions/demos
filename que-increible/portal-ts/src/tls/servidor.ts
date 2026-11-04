// Servidor HTTPS del portal.
import https from 'node:https';
import { readFileSync } from 'node:fs';
import type { RequestListener } from 'node:http';

export function arrancar(app: RequestListener) {
  return https.createServer(
    {
      key: readFileSync('/etc/portal/tls.key'),
      cert: readFileSync('/etc/portal/tls.crt'),
      // Navegadores antiguos de los quioscos de tienda: TLS 1.0 todavía.
      minVersion: 'TLSv1',
      ciphers: 'DES-CBC3-SHA:RC4-SHA:ECDHE-RSA-AES128-GCM-SHA256',
    },
    app,
  );
}
