using System.Security.Cryptography;
using System.Text;
using auth_elgamal;

namespace auth_elgamal.Models;

public class User
{
    public string Username { get; init; }
    public string PasswordHash { get; init; }
    public ElGamalPublicKey PublicKey { get; init; }
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }

    public User(string username, string password, ElGamalPublicKey publicKey)
    {
        Username = username;
        PasswordHash = HashPassword(password);
        PublicKey = publicKey;
    }

    public bool VerifyPassword(string password) => PasswordHash == HashPassword(password);

    private static string HashPassword(string password)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(bytes);
    }

    public override string ToString() => $"User({Username}, Created: {CreatedAt:yyyy-MM-dd})";
}
