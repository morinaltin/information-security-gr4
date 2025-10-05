using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace auth_elgamal;

public record ElGamalSignature(BigInteger R, BigInteger S)
{
    public override string ToString()
    {
        static string Short(BigInteger n)
        {
            var s = n.ToString();
            return s.Length > 20 ? s[..20] + "..." : s;
        }
        return $"Signature(R={Short(R)}, S={Short(S)})";
    }
}

public static class ElGamalSignatureOps
{
    public static ElGamalSignature Sign(string message, ElGamalKeyPair keyPair) =>
        Sign(Encoding.UTF8.GetBytes(message), keyPair);
    public static ElGamalSignature Sign(byte[] message, ElGamalKeyPair keyPair)
    {
        var (pub, prv) = keyPair;
        BigInteger p = pub.P;
        BigInteger g = pub.G;
        BigInteger x = prv.X;

        BigInteger h = HashToNumber(message);

        BigInteger k, r, s;
        do
        {
            do
            {
                k = CryptoUtils.GenerateRandomInRange(2, p - 2);
            } while (BigInteger.GreatestCommonDivisor(k, p - 1) != BigInteger.One);

            r = BigInteger.ModPow(g, k, p);                     
            var kInv = CryptoUtils.ModInverse(k, p - 1);        

            s = (h - x * r) * kInv % (p - 1);                   
            if (s < 0) s += (p - 1);
        } while (s == 0); 

        return new ElGamalSignature(r, s);
    }

    public static bool Verify(string message, ElGamalSignature sig, ElGamalPublicKey pub) =>
        Verify(Encoding.UTF8.GetBytes(message), sig, pub);

    public static bool Verify(byte[] message, ElGamalSignature sig, ElGamalPublicKey pub)
    {
        BigInteger p = pub.P;
        BigInteger g = pub.G;
        BigInteger y = pub.Y;

        BigInteger r = sig.R;
        BigInteger s = sig.S;

        if (r <= 0 || r >= p) return false;

        BigInteger h = HashToNumber(message);

        BigInteger left = BigInteger.ModPow(g, h, p);
        BigInteger right = (BigInteger.ModPow(y, r, p) * BigInteger.ModPow(r, s, p)) % p;

        return left == right;
    }
    private static BigInteger HashToNumber(byte[] message)
    {
        byte[] hash = SHA256.HashData(message);
        return new BigInteger(hash, isUnsigned: true);
    }
}
