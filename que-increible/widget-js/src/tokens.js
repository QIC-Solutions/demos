// Tokens de tarjeta y recibos. El formato de 2014 sigue vivo para las tiendas
// que no han actualizado el widget.
'use strict';

const crypto = require('node:crypto');

// Ficticio: no corresponde a ningún servicio real.
const SECRETO_RECIBOS = 'qic-demo-secreto-widget-2014';
const ALGORITMO_NUEVO = 'aes-256-gcm';

function tokenAntiguo(clave, iv, pan) {
  const c = crypto.createCipheriv('des-ede3-cbc', clave, iv);
  return Buffer.concat([c.update(pan), c.final()]);
}

function huellaDeTarjeta(pan) {
  return crypto.createHash('md5').update(pan).digest('hex');
}

function firmaDeLaPeticion(cuerpo) {
  return crypto.createHmac('sha1', SECRETO_RECIBOS).update(cuerpo).digest('base64');
}

function clavesDeRecibos() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 1024, publicExponent: 0x10001 });
}

function firmarRecibo(recibo, privada) {
  const firmante = crypto.createSign('RSA-SHA1');
  firmante.update(recibo);
  return firmante.sign(privada, 'base64');
}

function tokenNuevo(clave, iv, pan) {
  const c = crypto.createCipheriv(ALGORITMO_NUEVO, clave, iv);
  return Buffer.concat([c.update(pan), c.final(), c.getAuthTag()]);
}

module.exports = { tokenAntiguo, huellaDeTarjeta, firmaDeLaPeticion, clavesDeRecibos, firmarRecibo, tokenNuevo };
