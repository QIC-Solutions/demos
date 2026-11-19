// Lo ya post-cuántico: el sobre híbrido del token, con ML-KEM-768 y X25519
// (Node.js 22 con OpenSSL 3.5).
'use strict';

const crypto = require('node:crypto');

function clavesPostCuanticas() {
  return crypto.generateKeyPairSync('ml-kem-768');
}

function clavesClasicas() {
  return crypto.generateKeyPairSync('x25519');
}

module.exports = { clavesPostCuanticas, clavesClasicas };
