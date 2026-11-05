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

// Facturacion: el sistema de facturación usa ahora AES-256-GCM (3DES retirado por NIST).
// La clave debe ser de 32 bytes (256 bits). La salida es nonce || texto cifrado || tag.
// Imports necesarios: "crypto/aes", "crypto/cipher", "crypto/rand", "errors", "io".
func Facturacion(clave, bloque []byte) ([]byte, error) {
	if len(clave) != 32 {
		return nil, errors.New("cifrado: la clave AES-256 debe tener 32 bytes")
	}
	c, err := aes.NewCipher(clave)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	salida := gcm.Seal(nonce, nonce, bloque, nil)
	return salida, nil
}
	c.Encrypt(salida, bloque)
	return salida, nil
}
