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

// Imports necesarios:
//   "crypto/ed25519"
//   "github.com/cloudflare/circl/sign/mldsa/mldsa65"

// FirmarHibrida: firma compuesta Ed25519 + ML-DSA-65 (NIST FIPS 204).
// Salida: firmaEd25519 (64 bytes) || firmaMLDSA65 (mldsa65.SignatureSize bytes).
// El verificador DEBE validar ambas firmas; si una falla, la firma es inválida.
func FirmarHibrida(claveEd ed25519.PrivateKey, claveML *mldsa65.PrivateKey, datos []byte) ([]byte, error) {
	firmaEd := ed25519.Sign(claveEd, datos)
	firmaML := make([]byte, mldsa65.SignatureSize)
	// ctx vacío y firma determinista (false); ML-DSA aplica su propio hash interno,
	// por lo que ya no se pre-hashea con SHA-256.
	if err := mldsa65.SignTo(claveML, datos, nil, false, firmaML); err != nil {
		return nil, err
	}
	return append(firmaEd, firmaML...), nil
}

// FirmarTraza: ECDSA P-256 para la cabecera X-Traza.
// NOTA: ECDSA también es vulnerable a Shor; migrar igualmente a FirmarHibrida.
func FirmarTraza(datos []byte) ([]byte, error) {
	clave, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(datos)
	return ecdsa.SignASN1(rand.Reader, clave, h[:])
}
