using System.Security.Cryptography;
using Xunit;

namespace QueIncreible.Backoffice.Tests;

/// <summary>Pruebas: lo débil de aquí cuenta como «solo pruebas».</summary>
public class CifradoNominasTests
{
    [Fact]
    public void AesGcmDeJuguete()
    {
        var clave = RandomNumberGenerator.GetBytes(32); // 256 bits
        using var aes = new AesGcm(clave, AesGcm.TagByteSizes.MaxSize);
        Assert.Equal(32, clave.Length);
        Assert.Equal(12, AesGcm.NonceByteSizes.MaxSize);
        Assert.Equal(16, AesGcm.TagByteSizes.MaxSize);
    }

    [Fact]
    public void HuellaSha1DelFixture()
    {
        Assert.Equal(20, SHA1.HashData(new byte[] { 1, 2, 3 }).Length);
    }
}
