// Pruebas: lo débil de aquí cuenta como «solo pruebas».
import { test } from 'node:test';
import assert from 'node:assert';
import { createCipheriv, createHash } from 'node:crypto';

test('huella md4 del fixture', () => {
  assert.equal(createHash('md4').update('fixture').digest('hex').length, 32);
});

test('aes-256-gcm de juguete', () => {
  const key = randomBytes(32); // 256 bits, nunca una clave literal en el código
  const iv = randomBytes(12);  // nonce de 96 bits, único por cifrado
  const c = createCipheriv('aes-256-gcm', key, iv);
  assert.ok(c.update('12345678'));
  c.final();
  assert.equal(c.getAuthTag().length, 16);
});
