// Pasarela API interna de Que Increible Compañia SL (empresa ficticia de demo).
// Recibe el tráfico de la tienda, el portal y la app y lo reparte a los
// servicios internos.
package main

import (
	"log"
	"net/http"

	"queincreible/gateway/internal/tlsconf"
)

func main() {
	srv := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsconf.Servidor(),
	}
	log.Fatal(srv.ListenAndServeTLS("/etc/gateway/tls.crt", "/etc/gateway/tls.key"))
}
