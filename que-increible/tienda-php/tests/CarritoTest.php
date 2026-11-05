<?php

use PHPUnit\Framework\TestCase;

/** Pruebas: lo débil de aquí cuenta como «solo pruebas». */
final class CarritoTest extends TestCase
{
    public function testHuellaSha256DelFixture(): void
    {
        // SHA-256 en hex produce 64 caracteres (MD5 producía 32)
        $this->assertSame(64, strlen(hash_file('sha256', __DIR__ . '/fixture.json')));
    }

    public function testBlowfishDeJuguete(): void
    {
        $this->assertNotFalse(openssl_encrypt('hola', 'bf-ecb', 'clave-de-prueba'));
    }
}
