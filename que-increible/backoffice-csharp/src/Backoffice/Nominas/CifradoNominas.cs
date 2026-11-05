using System.Security.Cryptography;
using System.Text;

namespace QueIncreible.Backoffice.Nominas;

/// <summary>
/// Cifrado de las nóminas en PDF antes de dejarlas en el portal del empleado,
/// y del IBAN en la base de RR. HH.
/// </summary>
public class CifradoNominas
{
    // DEMO — clave fija en el código (ficticia).
    private const string MasterKey = "QmFja29mZmljZVF1ZUluY3JlaWJsZURlbW8xMjM0NTY=";

    /// <summary>IBAN: versión de 2015, AES con modo ECB.</summary>
    public byte[] CifrarIban(string iban)
    {
        using var aes = Aes.Create();
        aes.Key = Convert.FromBase64String(MasterKey)[..16];
        aes.Mode = CipherMode.ECB;
        using var cifrador = aes.CreateEncryptor();
        var datos = Encoding.UTF8.GetBytes(iban);
        return cifrador.TransformFinalBlock(datos, 0, datos.Length);
    }

    /// <summary>Nómina en PDF: AES-256-GCM.</summary>
    public byte[] CifrarNomina(byte[] pdf, byte[] clave)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var salida = new byte[pdf.Length];
        var etiqueta = new byte[16];
        using var gcm = new AesGcm(clave, 16);
        gcm.Encrypt(nonce, pdf, salida, etiqueta);
        return [.. nonce, .. salida, .. etiqueta];
    }

    /// <summary>La gestoría externa debe aceptar ficheros en AES-256-GCM (3DES retirado por NIST SP 800-131A).</summary>
    public byte[] CifrarParaGestoria(byte[] fichero, byte[] clave256)
    {
        if (clave256.Length != 32)
            throw new ArgumentException("La clave debe ser de 256 bits (32 bytes)", nameof(clave256));

        var nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // 12 bytes, único por fichero
        RandomNumberGenerator.Fill(nonce);

        var tag = new byte[AesGcm.TagByteSizes.MaxSize];     // 16 bytes de autenticación
        var cifrado = new byte[fichero.Length];

        using var aes = new AesGcm(clave256, tag.Length);
        aes.Encrypt(nonce, fichero, cifrado, tag);

        // Formato de salida acordado con la gestoría: nonce || tag || cifrado
        var resultado = new byte[nonce.Length + tag.Length + cifrado.Length];
        Buffer.BlockCopy(nonce, 0, resultado, 0, nonce.Length);
        Buffer.BlockCopy(tag, 0, resultado, nonce.Length, tag.Length);
        Buffer.BlockCopy(cifrado, 0, resultado, nonce.Length + tag.Length, cifrado.Length);
        return resultado;
    }

    /// <summary>Contraseña del portal del empleado: PBKDF2 con HMAC-SHA256 (NIST SP 800-132) y 600.000 iteraciones.</summary>
    public byte[] DerivarClave(string contrasena, byte[] sal)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(contrasena, sal, 600000, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(32);
    }
}
