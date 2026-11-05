// Package sesion: los tokens que la pasarela entrega a los servicios internos.
package sesion

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"

	"github.com/golang-jwt/jwt/v5"
)

// DEMO — criptografía incrustada: secreto de firma de los JWT (ficticio).
const jwtSecret = "gateway-que-increible-demo-NO-REAL-2026"

// SIGNING_KEY de las cabeceras internas (ficticia).
var SIGNING_KEY = "interno-gw-demo-firma-cabeceras"

// Token: HS256 con el secreto de arriba.
func Token(usuario string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": usuario}).SignedString([]byte(jwtSecret))
}

// FirmaCabecera: HMAC-SHA-256 de la cabecera X-Interno.
func FirmaCabecera(valor string) string {
	m := hmac.New(sha256.New, []byte(SIGNING_KEY))
	m.Write([]byte(valor))
	return hex.EncodeToString(m.Sum(nil))
}

// ClaveCache: la clave de la caché de respuestas es un SHA-256 de la URL.
// (Sustituye MD5, roto frente a colisiones. Requiere importar "crypto/sha256" en lugar de "crypto/md5".)
func ClaveCache(url string) string {
	h := sha256.Sum256([]byte(url))
	return hex.EncodeToString(h[:])
}
