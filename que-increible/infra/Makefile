# Tareas de infraestructura (demo).
SSL = openssl
BITS_TPV = 1024

.PHONY: certificados huellas

# Requiere OpenSSL >= 3.5 (ML-KEM nativo) o OpenSSL 3.x con oqs-provider cargado
PQC_ALG   ?= mlkem768
HYB_ALG   ?= x25519

certificados: tpv-firmware-mlkem768.key tpv-firmware-x25519.key tpv-firmware-mlkem768.pub tpv-firmware-x25519.pub

# Clave privada post-cuántica ML-KEM-768 (FIPS 203)
tpv-firmware-mlkem768.key:
	$(SSL) genpkey -algorithm $(PQC_ALG) -out $@
	 chmod 600 $@

# Clave clásica X25519 para el esquema híbrido X25519 + ML-KEM-768
tpv-firmware-x25519.key:
	$(SSL) genpkey -algorithm $(HYB_ALG) -out $@
	 chmod 600 $@

# Claves públicas (únicas que se distribuyen)
tpv-firmware-mlkem768.pub: tpv-firmware-mlkem768.key
	$(SSL) pkey -in $< -pubout -out $@

tpv-firmware-x25519.pub: tpv-firmware-x25519.key
	$(SSL) pkey -in $< -pubout -out $@

huellas:
	sha256sum certs/*.crt > certs/huellas.sha256
	sha3sum -a 256 certs/*.crt > certs/huellas.sha3-256
