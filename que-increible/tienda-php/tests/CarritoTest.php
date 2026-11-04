<?php

use PHPUnit\Framework\TestCase;

/** Pruebas: lo débil de aquí cuenta como «solo pruebas». */
final class CarritoTest extends TestCase
{
    public function testHuellaMd5DelFixture(): void
    {
        $this->assertSame(32, strlen(md5_file(__DIR__ . '/fixture.json')));
    }

    public function testBlowfishDeJuguete(): void
    {
        $this->assertNotFalse(openssl_encrypt('hola', 'bf-ecb', 'clave-de-prueba'));
    }
}
