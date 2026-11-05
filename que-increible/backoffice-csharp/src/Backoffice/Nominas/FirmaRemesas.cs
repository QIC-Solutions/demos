using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;

namespace QueIncreible.Backoffice.Nominas;

/// <summary>Firma de las remesas SEPA de nóminas que se envían al banco.</summary>
public class FirmaRemesas(IConfiguration configuracion)
{
    /// <summary>Firma híbrida post-cuántica: ML-DSA-65 (FIPS 204) + ECDSA P-256/SHA-256. Sustituye al proveedor RSA-1024/SHA-1.</summary>
    public byte[] FirmarRemesaHeredada(byte[] remesa)
    {
        // Claves cargadas desde el almacén seguro (ver pasos de regeneración); nunca generarlas aquí.
        var clavePqc = (MLDsaPrivateKeyParameters)PrivateKeyFactory.CreateKey(File.ReadAllBytes("mldsa65_priv.der"));
        var firmadorPqc = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
        firmadorPqc.Init(true, clavePqc);
        firmadorPqc.BlockUpdate(remesa, 0, remesa.Length);
        byte[] firmaPqc = firmadorPqc.GenerateSignature();

        // Componente clásica del esquema híbrido (API nativa de .NET)
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ecdsa.ImportPkcs8PrivateKey(File.ReadAllBytes("ecdsa_p256_priv.der"), out _);
        byte[] firmaClasica = ecdsa.SignData(remesa, HashAlgorithmName.SHA256);

        // Formato híbrido: [len_pqc (4 bytes BE)][firmaPqc][firmaClasica]; el verificador exige AMBAS válidas.
        byte[] len = BitConverter.GetBytes(firmaPqc.Length);
        if (BitConverter.IsLittleEndian) Array.Reverse(len);
        return len.Concat(firmaPqc).Concat(firmaClasica).ToArray();
    }

    public byte[] FirmarRemesa(byte[] remesa)
    {
        // Firma post-cuántica ML-DSA-65 (FIPS 204). En producción la clave privada
        // debe cargarse desde el almacén de claves (KeyVault/HSM), no generarse por llamada.
        var generador = new MLDsaKeyPairGenerator();
        generador.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), MLDsaParameters.ml_dsa_65));
        AsymmetricCipherKeyPair par = generador.GenerateKeyPair();

        var firmador = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
        firmador.Init(true, par.Private);
        firmador.BlockUpdate(remesa, 0, remesa.Length);
        return firmador.GenerateSignature();
    }

    using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

    /// <summary>Justificante para el empleado: firma híbrida Ed25519 + ML-DSA-65 (FIPS 204).</summary>
    public byte[] FirmarJustificante(byte[] justificante)
    {
        var random = new SecureRandom();

        // Firma post-cuántica ML-DSA-65 (FIPS 204)
        // NOTA: en producción cargar la clave desde el almacén seguro en lugar de generarla por llamada.
        var mldsaGen = new MLDsaKeyPairGenerator();
        mldsaGen.Init(new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_65));
        AsymmetricCipherKeyPair mldsaKeys = mldsaGen.GenerateKeyPair();
        var mldsaSigner = new MLDsaSigner();
        mldsaSigner.Init(true, mldsaKeys.Private);
        mldsaSigner.BlockUpdate(justificante, 0, justificante.Length);
        byte[] firmaMlDsa = mldsaSigner.GenerateSignature();

        // Firma clásica Ed25519 (componente de transición del esquema híbrido)
        var edGen = new Ed25519KeyPairGenerator();
        edGen.Init(new Ed25519KeyGenerationParameters(random));
        AsymmetricCipherKeyPair edKeys = edGen.GenerateKeyPair();
        var edSigner = new Ed25519Signer();
        edSigner.Init(true, edKeys.Private);
        edSigner.BlockUpdate(justificante, 0, justificante.Length);
        byte[] firmaEd = edSigner.GenerateSignature();

        // Firma compuesta: [longitud Ed25519 (4 bytes BE)] || firma Ed25519 || firma ML-DSA-65
        // El verificador debe validar AMBAS firmas.
        var firmaCompuesta = new byte[4 + firmaEd.Length + firmaMlDsa.Length];
        firmaCompuesta[0] = (byte)(firmaEd.Length >> 24);
        firmaCompuesta[1] = (byte)(firmaEd.Length >> 16);
        firmaCompuesta[2] = (byte)(firmaEd.Length >> 8);
        firmaCompuesta[3] = (byte)firmaEd.Length;
        Buffer.BlockCopy(firmaEd, 0, firmaCompuesta, 4, firmaEd.Length);
        Buffer.BlockCopy(firmaMlDsa, 0, firmaCompuesta, 4 + firmaEd.Length, firmaMlDsa.Length);
        return firmaCompuesta;
    }

    /// <summary>Clave de sesión con la gestoría: híbrido X25519 + ML-KEM-768 (FIPS 203).</summary>
    /// <remarks>
    /// La gestoría debe publicar ahora dos claves (X25519 y ML-KEM-768). Devolvemos además el
    /// cifrado KEM y nuestra pública X25519 efímera, que hay que enviarle para que decapsule.
    /// </remarks>
    public byte[] AcuerdoGestoria(
        X25519PublicKeyParameters x25519Gestoria,
        MLKemPublicKeyParameters mlkemGestoria,
        out byte[] cifradoKem,
        out byte[] x25519PublicaPropia)
    {
        var rnd = new SecureRandom();

        // 1) Parte clásica: X25519 efímero
        var genX25519 = new X25519KeyPairGenerator();
        genX25519.Init(new X25519KeyGenerationParameters(rnd));
        var parEfimero = genX25519.GenerateKeyPair();
        var acuerdo = new X25519Agreement();
        acuerdo.Init(parEfimero.Private);
        var secretoClasico = new byte[acuerdo.AgreementSize];
        acuerdo.CalculateAgreement(x25519Gestoria, secretoClasico, 0);
        x25519PublicaPropia = ((X25519PublicKeyParameters)parEfimero.Public).GetEncoded();

        // 2) Parte post-cuántica: encapsulado ML-KEM-768
        var encapsulador = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        encapsulador.Init(new ParametersWithRandom(mlkemGestoria, rnd));
        cifradoKem = new byte[encapsulador.EncapsulationLength];
        var secretoPqc = new byte[encapsulador.SecretLength];
        encapsulador.Encapsulate(cifradoKem, 0, cifradoKem.Length, secretoPqc, 0, secretoPqc.Length);

        // 3) Combinación de secretos vía KDF (HKDF-SHA384) -> clave de sesión de 48 bytes
        var ikm = new byte[secretoClasico.Length + secretoPqc.Length];
        Buffer.BlockCopy(secretoClasico, 0, ikm, 0, secretoClasico.Length);
        Buffer.BlockCopy(secretoPqc, 0, ikm, secretoClasico.Length, secretoPqc.Length);
        try
        {
            return HKDF.DeriveKey(
                HashAlgorithmName.SHA384,
                ikm,
                outputLength: 48,
                salt: null,
                info: Encoding.UTF8.GetBytes("backoffice/gestoria/x25519-mlkem768/v1"));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretoClasico);
            CryptographicOperations.ZeroMemory(secretoPqc);
            CryptographicOperations.ZeroMemory(ikm);
        }
    }

    /// <summary>La versión ágil: el resumen sale de appsettings.json.</summary>
    public byte[] Resumen(byte[] datos)
    {
        using var resumen = HashAlgorithm.Create(configuracion["Seguridad:AlgoritmoResumen"]!)!;
        return resumen.ComputeHash(datos);
    }

    /// <summary>Huella del fichero de la gestoría: SHA-384 (FIPS 180-4, resistente a colisiones y apto para retención de larga duración).</summary>
    public byte[] HuellaFichero(byte[] fichero) => SHA384.HashData(fichero);
}
