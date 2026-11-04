using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Authentication;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace QueIncreible.Backoffice.Seguridad;

/// <summary>Tokens del portal del empleado y conexión con el banco.</summary>
public static class TokensEmpleado
{
    // DEMO — secreto JWT incrustado (ficticio).
    private const string jwtSecret = "backoffice-que-increible-demo-NO-REAL-2026!";

    public static string Emitir(string empleado)
    {
        var clave = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
        var credenciales = new SigningCredentials(clave, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(issuer: "backoffice", claims: null, signingCredentials: credenciales);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>El banco de las remesas (2014) solo acepta TLS 1.0 y 1.1.</summary>
    public static void ConfigurarBancoHeredado()
    {
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11;
    }

    public static SslProtocols ProtocolosNuevos() => SslProtocols.Tls13;
}
