// Package pqc: canal post-cuántico con el servicio de pagos (Go 1.24, crypto/mlkem).
package pqc

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
)

// NuevaClave: la pasarela publica una clave de encapsulado ML-KEM-768.
func NuevaClave() (*mlkem.DecapsulationKey768, error) {
	return mlkem.GenerateKey768()
}

// Encapsular: el secreto compartido con el servicio de pagos.
func Encapsular(publica []byte) (secreto, cifrado []byte, err error) {
	ek, err := mlkem.NewEncapsulationKey768(publica)
	if err != nil {
		return nil, nil, err
	}
	secreto, cifrado = ek.Encapsulate()
	return secreto, cifrado, nil
}

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
)

// ClaveHibrida: reemplaza al ECDH P-256 clásico por un acuerdo de clave
// híbrido X25519 + ML-KEM-768 (FIPS 203). Los servicios aún no migrados
// deben pasar por esta ruta; la clásica queda deprecada.
type ClaveHibrida struct {
	X25519 *ecdh.PrivateKey
	MLKEM  *mlkem.DecapsulationKey768
}

// GenerarClaveHibrida genera el par híbrido (X25519 + ML-KEM-768).
func GenerarClaveHibrida() (*ClaveHibrida, error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &ClaveHibrida{X25519: x, MLKEM: dk}, nil
}

// ClavesPublicas devuelve las claves públicas a enviar al par.
func (k *ClaveHibrida) ClavesPublicas() (pubX25519 []byte, pubMLKEM []byte) {
	return k.X25519.PublicKey().Bytes(), k.MLKEM.EncapsulationKey().Bytes()
}

// SecretoCompartido combina el secreto X25519 y el secreto ML-KEM-768
// (obtenido al desencapsular el ciphertext del par) vía HKDF-SHA256.
func (k *ClaveHibrida) SecretoCompartido(peerX25519 []byte, ctMLKEM []byte) ([]byte, error) {
	peerPub, err := ecdh.X25519().NewPublicKey(peerX25519)
	if err != nil {
		return nil, err
	}
	ssX, err := k.X25519.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	ssK, err := k.MLKEM.Decapsulate(ctMLKEM)
	if err != nil {
		return nil, err
	}
	ikm := append(append([]byte{}, ssX...), ssK...)
	return hkdf.Key(sha256.New, ikm, nil, "gateway-go hybrid X25519+ML-KEM-768 v1", 32)
}

// ClaveClasica: DEPRECADA. ECDH sobre P-256 no es quantum-safe; se mantiene
// solo hasta completar la migración y debe eliminarse en la siguiente release.
//
// Deprecated: usar GenerarClaveHibrida.
func ClaveClasica() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}
