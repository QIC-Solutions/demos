# frozen_string_literal: true

# Solo en pruebas: resúmenes débiles para fabricar extractos de ejemplo.
require 'digest'
require_relative '../lib/integraciones/banco'

RSpec.describe QueIncreible::Integraciones::Banco do
  it 'calcula el control del extracto' do
    extracto = 'IBAN;IMPORTE'
    expect(Digest::MD5.hexdigest(extracto).size).to eq(32)
    expect(Digest::SHA1.hexdigest(extracto).size).to eq(40)
  end
end
