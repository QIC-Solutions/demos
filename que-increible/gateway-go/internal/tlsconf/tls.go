// Package tlsconf: la configuración TLS de la pasarela.
package tlsconf

import (
	"crypto/tls"
	"os"
)

// Servidor: TLS 1.2 como mínimo y, primero, el intercambio híbrido
// post-cuántico X25519MLKEM768 (Go 1.24).
func Servidor() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
	}
}

// ClienteFacturacion: el sistema de facturación externo (2013) solo habla
// TLS 1.0 con 3DES. Se mantiene «temporalmente» desde 2019.
func ClienteFacturacion() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS11,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_RSA_WITH_RC4_128_SHA},
	}
}

// ClienteInterno: la versión mínima se elige en el despliegue.
func ClienteInterno() *tls.Config {
	minima := tls.VersionTLS12
	if os.Getenv("GATEWAY_TLS13") == "1" {
		minima = tls.VersionTLS13
	}
	return &tls.Config{MinVersion: uint16(minima)}
}
