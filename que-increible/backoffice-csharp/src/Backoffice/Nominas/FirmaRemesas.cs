using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;

namespace QueIncreible.Backoffice.Nominas;

/// <summary>Firma de las remesas SEPA de nóminas que se envían al banco.</summary>
public class FirmaRemesas(IConfiguration configuracion)
{
    /// <summary>Proveedor heredado: sin tamaño, .NET crea una clave RSA-1024.</summary>
    public byte[] FirmarRemesaHeredada(byte[] remesa)
    {
        using var rsa = new RSACryptoServiceProvider();
        return rsa.SignData(remesa, SHA1.Create());
    }

    public byte[] FirmarRemesa(byte[] remesa)
    {
        using var rsa = RSA.Create(3072);
        return rsa.SignData(remesa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    /// <summary>Justificante para el empleado: ECDSA P-256.</summary>
    public byte[] FirmarJustificante(byte[] justificante)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return ecdsa.SignData(justificante, HashAlgorithmName.SHA256);
    }

    /// <summary>Clave de sesión con la gestoría: ECDH P-384.</summary>
    public byte[] AcuerdoGestoria(ECDiffieHellmanPublicKey publicaGestoria)
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
        return ecdh.DeriveKeyMaterial(publicaGestoria);
    }

    /// <summary>La versión ágil: el resumen sale de appsettings.json.</summary>
    public byte[] Resumen(byte[] datos)
    {
        using var resumen = HashAlgorithm.Create(configuracion["Seguridad:AlgoritmoResumen"]!)!;
        return resumen.ComputeHash(datos);
    }

    /// <summary>Huella del fichero de la gestoría: MD5.</summary>
    public byte[] HuellaFichero(byte[] fichero) => MD5.HashData(fichero);
}
