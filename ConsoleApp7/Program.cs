using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;


string source = "Hello World!";
using (SHA256 sha256Hash = SHA256.Create())
{
    string hash = Hash.GetHash(sha256Hash, source);

    Console.WriteLine($"The SHA256 hash of {source} is: {hash}.");

    Console.WriteLine("Verifying the hash...");

    if (Hash.VerifyHash(sha256Hash, source, hash))
    {
        Console.WriteLine("The hashes are the same.");
    }
    else
    {
        Console.WriteLine("The hashes are not same.");
    }
}


var key = Convert.FromBase64String(
    "XCAP05H6LoKvbRRa/QkqLNMI7cOHguaRyHzyg7n5qEkGjQmtBhz4SzYh4Fqwjyi3KJHlSXKPwVu2+bXr6CtpgQ==");

var securityKey = new SymmetricSecurityKey(key);
var descriptor = new SecurityTokenDescriptor
{
    Subject = new ClaimsIdentity(new[]
    {
        new Claim("UserPass", "Дима28684.")
    }),
    SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature)
};

var handler = new JwtSecurityTokenHandler();
var token = handler.CreateJwtSecurityToken(descriptor);
var tolStr = handler.WriteToken(token);
var pass = tolStr.DecodingToken();

Console.WriteLine(tolStr);
Console.WriteLine(pass);
Console.ReadKey();


public static class Decoder
{
    public static string? DecodingToken(this string token)
    {
        var key = Convert.FromBase64String(
            "XCAP05H6LoKvbRRa/QkqLNMI7cOHguaRyHzyg7n5qEkGjQmtBhz4SzYh4Fqwjyi3KJHlSXKPwVu2+bXr6CtpgQ==");
        var tokenHandler = new JwtSecurityTokenHandler();
        var parameters = new TokenValidationParameters
        {
            RequireExpirationTime = true,
            ValidateIssuer = false,
            ValidateAudience = false,
            IssuerSigningKey = new SymmetricSecurityKey(key)
        };
        var principal = tokenHandler.ValidateToken(token, parameters, out var securityToken);
        return principal.Claims.FirstOrDefault(x => x.Type.Equals("UserPass"))?.Value;
    }
}

public static class Hash
{
    public static string GetHash(HashAlgorithm hashAlgorithm, string input)
    {

        // Convert the input string to a byte array and compute the hash.
        byte[] data = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(input));

        // Create a new Stringbuilder to collect the bytes
        // and create a string.
        var sBuilder = new StringBuilder();

        // Loop through each byte of the hashed data
        // and format each one as a hexadecimal string.
        for (int i = 0; i < data.Length; i++)
        {
            sBuilder.Append(data[i].ToString("x2"));
        }

        // Return the hexadecimal string.
        return sBuilder.ToString();
    }

    // Verify a hash against a string.
    public static bool VerifyHash(HashAlgorithm hashAlgorithm, string input, string hash)
    {
        // Hash the input.
        var hashOfInput = GetHash(hashAlgorithm, input);

        // Create a StringComparer an compare the hashes.
        StringComparer comparer = StringComparer.OrdinalIgnoreCase;

        return comparer.Compare(hashOfInput, hash) == 0;
    }
}