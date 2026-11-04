// Package firma: firma de las respuestas y de las cabeceras de trazabilidad.
package firma

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
)

// ClaveRespuestas: RSA-2048 para firmar respuestas (vulnerable ante Shor).
func ClaveRespuestas() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// ClaveSociosAntiguos: los socios de 2012 solo validan RSA-1024.
func ClaveSociosAntiguos() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 1024)
}

// FirmarHeredado: PKCS#1 v1.5 con SHA-1, prohibido al firmar.
func FirmarHeredado(clave *rsa.PrivateKey, datos []byte) ([]byte, error) {
	h := sha1.Sum(datos)
	return rsa.SignPKCS1v15(rand.Reader, clave, crypto.SHA1, h[:])
}

// FirmarPSS: RSA-PSS con SHA-256.
func FirmarPSS(clave *rsa.PrivateKey, datos []byte) ([]byte, error) {
	h := sha256.Sum256(datos)
	return rsa.SignPSS(rand.Reader, clave, crypto.SHA256, h[:], nil)
}

// FirmarTraza: ECDSA P-256 para la cabecera X-Traza.
func FirmarTraza(datos []byte) ([]byte, error) {
	clave, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(datos)
	return ecdsa.SignASN1(rand.Reader, clave, h[:])
}
