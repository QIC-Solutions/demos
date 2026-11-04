using System.Security.Cryptography;
using Xunit;

namespace QueIncreible.Backoffice.Tests;

/// <summary>Pruebas: lo débil de aquí cuenta como «solo pruebas».</summary>
public class CifradoNominasTests
{
    [Fact]
    public void DesDeJuguete()
    {
        using var des = DES.Create();
        Assert.Equal(8, des.BlockSize / 8);
    }

    [Fact]
    public void HuellaSha1DelFixture()
    {
        Assert.Equal(20, SHA1.HashData(new byte[] { 1, 2, 3 }).Length);
    }
}
