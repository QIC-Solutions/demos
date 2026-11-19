# frozen_string_literal: true

# Extractos diarios del banco. El formato antiguo llega cifrado en 3DES con una
# clave pactada en 2009; el nuevo, en AES-256-GCM.
require 'openssl'
require 'digest'
require 'securerandom'

module QueIncreible
  module Integraciones
    class Banco
      # Ficticio: no corresponde a ningún servicio real.
      SECRETO_FIRMA = 'qic-demo-secreto-extractos-2009'

      def initialize(clave_3des, maestra)
        @clave_3des = clave_3des
        @maestra = maestra
      end

      def leer_extracto_antiguo(cifrado, iv)
        c = OpenSSL::Cipher.new('des-ede3-cbc')
        c.decrypt
        c.key = @clave_3des
        c.iv = iv
        c.update(cifrado) + c.final
      end

      def control(extracto)
        Digest::MD5.hexdigest(extracto)
      end

      def firma_valida?(extracto, firma)
        OpenSSL::HMAC.hexdigest('SHA1', SECRETO_FIRMA, extracto) == firma
      end

      def leer_extracto(cifrado, iv, etiqueta)
        clave = OpenSSL::KDF.hkdf(@maestra, salt: 'extractos', info: 'banco', length: 32, hash: 'SHA256')
        c = OpenSSL::Cipher::AES256.new(:GCM)
        c.decrypt
        c.key = clave
        c.iv = iv
        c.auth_tag = etiqueta
        c.update(cifrado) + c.final
      end

      def nonce
        SecureRandom.random_bytes(12)
      end
    end
  end
end
