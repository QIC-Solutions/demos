// El servidor del widget. Las tiendas asociadas más antiguas siguen con
// navegadores que no pasan de TLS 1.0, así que el mínimo se bajó en 2016 y nadie
// lo volvió a subir.
'use strict';

const https = require('node:https');
const tls = require('node:tls');

tls.DEFAULT_MIN_VERSION = 'TLSv1';

function servidorDelWidget(clave, certificado, manejar) {
  return https.createServer({ key: clave, cert: certificado, minVersion: 'TLSv1' }, manejar);
}

// El adquirente antiguo solo negocia TLS 1.0 con 3DES o RC4.
function contextoAdquirenteAntiguo() {
  return tls.createSecureContext({ secureProtocol: 'TLSv1_method', ciphers: 'DES-CBC3-SHA:RC4-SHA:!aNULL' });
}

// El adquirente nuevo: TLS 1.2 o 1.3.
function conexionAdquirenteNuevo(host) {
  return tls.connect(8443, host, { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3' });
}

module.exports = { servidorDelWidget, contextoAdquirenteAntiguo, conexionAdquirenteNuevo };
