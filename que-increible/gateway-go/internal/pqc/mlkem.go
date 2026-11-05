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

const infoHibrido = "que-increible/gateway-go hybrid X25519+ML-KEM-768 v1"

// ClaveHibrida: sustituye al antiguo ECDH sobre P-256. Combina X25519
// (clásico) con ML-KEM-768 (FIPS 203); el secreto final se deriva con
// HKDF-SHA256 a partir de ambos secretos, así que sigue siendo seguro aunque
// uno de los dos esquemas caiga.
type ClaveHibrida struct {
	X25519 *ecdh.PrivateKey
	MLKEM  *mlkem.DecapsulationKey768
}

// ClavePublicaHibrida: lo que se publica/distribuye al par.
type ClavePublicaHibrida struct {
	X25519 *ecdh.PublicKey
	MLKEM  *mlkem.EncapsulationKey768
}

// GenerarClaveHibrida reemplaza a ClaveClasica para TODOS los servicios
// (los no migrados deben pasar por aquí; no se mantiene P-256).
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

func (k *ClaveHibrida) Publica() ClavePublicaHibrida {
	return ClavePublicaHibrida{X25519: k.X25519.PublicKey(), MLKEM: k.MLKEM.EncapsulationKey()}
}

// Encapsular: lado iniciador. Devuelve el secreto compartido, el ciphertext
// ML-KEM y la clave pública efímera X25519 que hay que enviar al receptor.
func Encapsular(peer ClavePublicaHibrida) (secreto, ctKEM []byte, efimeraX *ecdh.PublicKey, err error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	ssX, err := eph.ECDH(peer.X25519)
	if err != nil {
		return nil, nil, nil, err
	}
	ssKEM, ctKEM := peer.MLKEM.Encapsulate()
	secreto, err = combinar(ssX, ssKEM)
	if err != nil {
		return nil, nil, nil, err
	}
	return secreto, ctKEM, eph.PublicKey(), nil
}

// Desencapsular: lado receptor.
func (k *ClaveHibrida) Desencapsular(efimeraX *ecdh.PublicKey, ctKEM []byte) ([]byte, error) {
	ssX, err := k.X25519.ECDH(efimeraX)
	if err != nil {
		return nil, err
	}
	ssKEM, err := k.MLKEM.Decapsulate(ctKEM)
	if err != nil {
		return nil, err
	}
	return combinar(ssX, ssKEM)
}

// combinar: KDF sobre la concatenación de ambos secretos (X25519 || ML-KEM).
func combinar(ssX, ssKEM []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(ssX)+len(ssKEM))
	ikm = append(ikm, ssX...)
	ikm = append(ikm, ssKEM...)
	return hkdf.Key(sha256.New, ikm, nil, infoHibrido, 32)
}
