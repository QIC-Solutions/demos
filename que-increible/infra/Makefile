# Tareas de infraestructura (demo).
SSL = openssl
BITS_TPV = 1024

.PHONY: certificados huellas

certificados: tpv-firmware.key

tpv-firmware.key:
	$(SSL) genrsa -out $@ $(BITS_TPV)

huellas:
	sha1sum certs/*.crt > certs/huellas.sha1
	sha256sum certs/*.crt > certs/huellas.sha256
