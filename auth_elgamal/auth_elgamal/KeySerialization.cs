using System.Numerics;
using System.Text.Json;

namespace auth_elgamal;

public static class KeySerialization
{

    public static string BigIntToBase64(BigInteger n)
    {
        if (n < 0) throw new ArgumentOutOfRangeException(nameof(n), "Only non-negative values supported");
        var bytes = n.ToByteArray(isUnsigned: true, isBigEndian: true);
        return Convert.ToBase64String(bytes);
    }
    
    public static BigInteger Base64ToBigInt(string base64)
    {
        var bytes = Convert.FromBase64String(base64);
        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
    }
    
    public static SerializedPublicKey ExportPublicKey(ElGamalPublicKey publicKey)
    {
        return new SerializedPublicKey(
            P: BigIntToBase64(publicKey.P),
            G: BigIntToBase64(publicKey.G),
            Y: BigIntToBase64(publicKey.Y)
        );
    }
    
    public static ElGamalPublicKey ImportPublicKey(SerializedPublicKey serialized)
    {
        return new ElGamalPublicKey(
            P: Base64ToBigInt(serialized.P),
            G: Base64ToBigInt(serialized.G),
            Y: Base64ToBigInt(serialized.Y)
        );
    }
    
    public static string PublicKeyToJson(SerializedPublicKey serialized, bool indented = true)
    {
        return JsonSerializer.Serialize(serialized, new JsonSerializerOptions{ WriteIndented = indented });
        }
    
    public static SerializedPublicKey PublicKeyFromJson(string json)
    {
        var obj = JsonSerializer.Deserialize<SerializedPublicKey>(json);
        if (obj is null) throw new FormatException("Invalid public key JSON");
        return obj;
    }
}
public record SerializedPublicKey(string P, string G, string Y);
