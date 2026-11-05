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

// Imports necesarios: crypto/ecdh, crypto/hkdf, crypto/mlkem, crypto/rand, crypto/sha256, crypto/rsa

// ClaveHibrida: par X25519 + ML-KEM-768 (FIPS 203) para proteger respuestas (resistente a Shor).
type ClaveHibrida struct {
	X25519 *ecdh.PrivateKey
	MLKEM  *mlkem.DecapsulationKey768
}

// ClaveRespuestas: híbrido X25519 + ML-KEM-768 para encapsular el secreto que protege las respuestas.
func ClaveRespuestas() (*ClaveHibrida, error) {
	kemKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	ecKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ClaveHibrida{X25519: ecKey, MLKEM: kemKey}, nil
}

// ClavePublica: bytes a distribuir al emisor (pub X25519 || pub ML-KEM-768).
func (k *ClaveHibrida) ClavePublica() (ecPub []byte, kemPub []byte) {
	return k.X25519.PublicKey().Bytes(), k.MLKEM.EncapsulationKey().Bytes()
}

// SecretoCompartido: descapsula ambos componentes y los combina vía HKDF-SHA256.
func (k *ClaveHibrida) SecretoCompartido(ctEC []byte, ctKEM []byte) ([]byte, error) {
	pubEC, err := ecdh.X25519().NewPublicKey(ctEC)
	if err != nil {
		return nil, err
	}
	ssEC, err := k.X25519.ECDH(pubEC)
	if err != nil {
		return nil, err
	}
	ssKEM, err := k.MLKEM.Decapsulate(ctKEM)
	if err != nil {
		return nil, err
	}
	ikm := append(append([]byte{}, ssEC...), ssKEM...)
	return hkdf.Key(sha256.New, ikm, nil, "gateway-go/respuestas X25519+ML-KEM-768 v1", 32)
}

// ClaveSociosAntiguos: los socios de 2012 solo validan RSA-1024.
// TODO: RSA-1024 está roto incluso clásicamente; planificar migración de los socios a ML-KEM-768 híbrido.
func ClaveSociosAntiguos() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 1024)
}

// FirmarHeredado: RSA-PSS con SHA-256 (SHA-1 y PKCS#1 v1.5 retirados de la firma).
// Requiere sustituir el import "crypto/sha1" por "crypto/sha256".
func FirmarHeredado(clave *rsa.PrivateKey, datos []byte) ([]byte, error) {
	h := sha256.Sum256(datos)
	return rsa.SignPSS(rand.Reader, clave, crypto.SHA256, h[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
}

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// FirmarHibrida: firma compuesta Ed25519 + ML-DSA-65 (FIPS 204) sobre SHA-256.
// Sustituye a FirmarPSS (RSA-PSS). Salida: firmaEd25519 (64 bytes) || firmaML-DSA-65 (3309 bytes).
// El verificador DEBE validar ambas firmas; si cualquiera falla, la firma es inválida.
func FirmarHibrida(claveEd ed25519.PrivateKey, claveML *mldsa65.PrivateKey, datos []byte) ([]byte, error) {
	h := sha256.Sum256(datos)
	firmaEd := ed25519.Sign(claveEd, h[:])
	firmaML, err := claveML.Sign(rand.Reader, h[:], crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	firma := make([]byte, 0, ed25519.SignatureSize+mldsa65.SignatureSize)
	firma = append(firma, firmaEd...)
	firma = append(firma, firmaML...)
	return firma, nil
}

// FirmarTraza: la cabecera X-Traza debe migrar igualmente de ECDSA P-256 a FirmarHibrida.
func FirmarTraza(datos []byte) ([]byte, error) {
	clave, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(datos)
	return ecdsa.SignASN1(rand.Reader, clave, h[:])
}
