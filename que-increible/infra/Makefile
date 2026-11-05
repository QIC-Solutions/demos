# Tareas de infraestructura (demo).
SSL = openssl
BITS_TPV = 1024

.PHONY: certificados huellas

# Esquema híbrido X25519 + ML-KEM-768 (NIST FIPS 203). Requiere OpenSSL 3.5+ u oqs-provider.
ALG_TPV ?= mlkem768

certificados: tpv-firmware.key tpv-firmware.pub tpv-firmware-x25519.key tpv-firmware-x25519.pub

# Clave privada post-cuántica ML-KEM-768 (sustituye a genrsa / $(BITS_TPV))
tpv-firmware.key:
	$(SSL) genpkey -algorithm $(ALG_TPV) -out $@

# Clave pública ML-KEM-768: es la ÚNICA que se distribuye a los TPV
tpv-firmware.pub: tpv-firmware.key
	$(SSL) pkey -in $< -pubout -out $@

# Componente clásico del híbrido (X25519)
tpv-firmware-x25519.key:
	$(SSL) genpkey -algorithm X25519 -out $@

tpv-firmware-x25519.pub: tpv-firmware-x25519.key
	$(SSL) pkey -in $< -pubout -out $@

# Huellas: se elimina SHA-1 (obsoleto); se mantiene SHA-256 y se añade SHA-512
huellas:
	sha256sum certs/*.crt > certs/huellas.sha256
	sha512sum certs/*.crt > certs/huellas.sha512
