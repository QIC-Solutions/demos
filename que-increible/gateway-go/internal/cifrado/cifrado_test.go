package cifrado

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"testing"
)

// Pruebas: lo débil de aquí cuenta como «solo pruebas».
func TestDesDeJuguete(t *testing.T) {
	if _, err := des.NewCipher([]byte("8bytes!!")); err != nil {
		t.Fatal(err)
	}
	if _, err := rc4.NewCipher([]byte("clave")); err != nil {
		t.Fatal(err)
	}
	_ = md5.Sum([]byte("fixture"))
}
