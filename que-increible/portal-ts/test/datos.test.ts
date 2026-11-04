// Pruebas: lo débil de aquí cuenta como «solo pruebas».
import { test } from 'node:test';
import assert from 'node:assert';
import { createCipheriv, createHash } from 'node:crypto';

test('huella md4 del fixture', () => {
  assert.equal(createHash('md4').update('fixture').digest('hex').length, 32);
});

test('des de juguete', () => {
  const c = createCipheriv('des-ecb', Buffer.from('8bytes!!'), null);
  assert.ok(c.update('12345678'));
});
