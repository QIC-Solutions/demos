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

    /// <summary>La gestoría externa solo lee ficheros en Triple DES.</summary>
    public byte[] CifrarParaGestoria(byte[] fichero)
    {
        using var tdes = TripleDES.Create();
        using var cifrador = tdes.CreateEncryptor();
        return cifrador.TransformFinalBlock(fichero, 0, fichero.Length);
    }

    /// <summary>Contraseña del portal del empleado: PBKDF2 con los valores de .NET (HMAC-SHA1).</summary>
    public byte[] DerivarClave(string contrasena, byte[] sal)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(contrasena, sal, 10000);
        return pbkdf2.GetBytes(32);
    }
}
