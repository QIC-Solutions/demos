// Solo en pruebas: resúmenes débiles para fabricar tarjetas de ejemplo.
'use strict';

const crypto = require('node:crypto');
const { huellaDeTarjeta } = require('../src/tokens');

test('la huella de una tarjeta tiene 32 caracteres', () => {
  const pan = '4000000000000002';
  expect(huellaDeTarjeta(pan)).toHaveLength(32);
  expect(crypto.createHash('sha1').update(pan).digest('hex')).toHaveLength(40);
  expect(crypto.createHash('md5').update(pan).digest('hex')).toHaveLength(32);
});
