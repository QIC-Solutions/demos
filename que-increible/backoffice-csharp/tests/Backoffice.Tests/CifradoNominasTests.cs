using System.Security.Cryptography;
using Xunit;

namespace QueIncreible.Backoffice.Tests;

/// <summary>Pruebas: lo débil de aquí cuenta como «solo pruebas».</summary>
public class CifradoNominasTests
// La generación automática no estuvo disponible. Aplicar la recomendación PQC indicada sobre el código detectado.
    public void HuellaSha1DelFixture()
    {
        Assert.Equal(20, SHA1.HashData(new byte[] { 1, 2, 3 }).Length);
    }
}
