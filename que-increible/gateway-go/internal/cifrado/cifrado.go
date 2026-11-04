// Package cifrado: cifrado de los datos que la pasarela deja en la caché.
package cifrado

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
)

// Cache: AES-GCM con la clave de 32 bytes que llega del gestor de secretos.
func Cache(clave, datos []byte) ([]byte, error) {
	bloque, err := aes.NewCipher(clave)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(bloque)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, datos, nil), nil
}

// Facturacion: el sistema de facturación espera Triple DES.
func Facturacion(clave, bloque []byte) ([]byte, error) {
	c, err := des.NewTripleDESCipher(clave)
	if err != nil {
		return nil, err
	}
	salida := make([]byte, len(bloque))
	c.Encrypt(salida, bloque)
	return salida, nil
}
