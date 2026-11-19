# frozen_string_literal: true

# El catálogo de los mayoristas. El más antiguo manda un fichero en RC4 con la
# clave sacada de una frase; los nuevos, por Faraday con TLS 1.2 o superior.
require 'openssl'
require 'faraday'

module QueIncreible
  module Integraciones
    class Catalogo
      FRASE = 'qic-demo-mayorista-1998'

      def descifrar_antiguo(datos, sal)
        clave = OpenSSL::PKCS5.pbkdf2_hmac_sha1(FRASE, sal, 1000, 16)
        c = OpenSSL::Cipher.new('rc4')
        c.decrypt
        c.key = clave
        c.update(datos) + c.final
      end

      def mayorista_nuevo(url)
        Faraday.new(url, ssl: { min_version: :TLS1_2 })
      end

      def contexto_moderno
        ctx = OpenSSL::SSL::SSLContext.new
        ctx.min_version = OpenSSL::SSL::TLS1_2_VERSION
        ctx.max_version = :TLS1_3
        ctx
      end
    end
  end
end
