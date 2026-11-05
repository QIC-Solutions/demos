package cifrado

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"testing"
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

// Pruebas: aquí también se usa AES-256-GCM; DES/RC4 no se admiten ni como «solo pruebas».
func TestAesGcmDeJuguete(t *testing.T) {
	clave := make([]byte, 32) // 256 bits
	if _, err := rand.Read(clave); err != nil {
		t.Fatal(err)
	}
	bloque, err := aes.NewCipher(clave)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(bloque)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	cifrado := aead.Seal(nil, nonce, []byte("hola"), nil)
	if _, err := aead.Open(nil, nonce, cifrado, nil); err != nil {
		t.Fatal(err)
	}
	_ = md5.Sum([]byte("fixture"))
}
