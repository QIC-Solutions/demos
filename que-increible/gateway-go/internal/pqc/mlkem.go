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

// ClaveClasica: lo que había antes, un ECDH sobre P-256 (sigue para los
// servicios que no se han migrado).
func ClaveClasica() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}
