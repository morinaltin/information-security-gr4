using System.Numerics;
using System.Security.Cryptography;

namespace auth_elgamal;

public record ElGamalPublicKey(BigInteger P, BigInteger G, BigInteger Y)
{
    public override string ToString() => $"PublicKey(P={P.ToString()[..20]}..., G={G}, Y={Y.ToString()[..20]}...)";
}

public record ElGamalPrivateKey(BigInteger X)
{
    public override string ToString() => "PrivateKey(X=***hidden***)";
}

public record ElGamalKeyPair(ElGamalPublicKey PublicKey, ElGamalPrivateKey PrivateKey);

public static class ElGamalKeyGeneration
{
    public static ElGamalKeyPair GenerateKeyPair(int bitLength = 2048)
    {
        Console.WriteLine($"Generating {bitLength}-bit ElGamal key pair...");
        
        BigInteger p = GenerateLargePrime(bitLength);
        Console.WriteLine("Prime p generated.");
        
        BigInteger g = FindGenerator(p);
        
        BigInteger x = CryptoUtils.GenerateRandomInRange(2, p - 2);
        
        BigInteger y = BigInteger.ModPow(g, x, p);
        Console.WriteLine("Key pair generated successfully.");
        
        var publicKey = new ElGamalPublicKey(p, g, y);
        var privateKey = new ElGamalPrivateKey(x);
        
        return new ElGamalKeyPair(publicKey, privateKey);
    }
    
    private static BigInteger GenerateLargePrime(int bitLength)
    {
        using var rng = RandomNumberGenerator.Create();
        byte[] bytes = new byte[bitLength / 8];
        
        BigInteger prime;
        int attempts = 0;
        do
        {
            rng.GetBytes(bytes);
            
            bytes[^1] |= 0x01; 
            bytes[0] |= 0x80; 
            
            prime = new BigInteger(bytes, isUnsigned: true);
            attempts++;
            
        } while (!CryptoUtils.IsProbablyPrime(prime, 20));
        
        Console.WriteLine($"Found prime after {attempts} attempts.");
        return prime;
    }

    private static BigInteger FindGenerator(BigInteger p)
    {
        return 2;
    }
}

public static class CryptoUtils
{
    public static bool IsProbablyPrime(BigInteger n, int iterations)
    {
        if (n < 2) return false;
        if (n == 2 || n == 3) return true;
        if (n % 2 == 0) return false;
        
        BigInteger d = n - 1;
        int r = 0;
        while (d % 2 == 0)
        {
            d /= 2;
            r++;
        }
        
        for (int i = 0; i < iterations; i++)
        {
            BigInteger a = GenerateRandomInRange(2, n - 2);
            BigInteger x = BigInteger.ModPow(a, d, n);
            
            if (x == 1 || x == n - 1)
                continue;
            
            bool continueWitnessLoop = false;
            for (int j = 0; j < r - 1; j++)
            {
                x = BigInteger.ModPow(x, 2, n);
                if (x == n - 1)
                {
                    continueWitnessLoop = true;
                    break;
                }
            }
            
            if (continueWitnessLoop)
                continue;
            
            return false;
        }
        
        return true;
    }
    
    public static BigInteger GenerateRandomInRange(BigInteger min, BigInteger max)
    {
        using var rng = RandomNumberGenerator.Create();
        BigInteger range = max - min + 1;
        
        int byteCount = range.ToByteArray().Length;
        byte[] bytes = new byte[byteCount];
        
        BigInteger result;
        do
        {
            rng.GetBytes(bytes);
            result = new BigInteger(bytes, isUnsigned: true);
        } while (result >= range);
        
        return result + min;
    }
    
    public static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger m0 = m, x0 = 0, x1 = 1;
        
        if (m == 1) return 0;
        
        while (a > 1)
        {
            BigInteger q = a / m;
            BigInteger t = m;
            
            m = a % m;
            a = t;
            t = x0;
            
            x0 = x1 - q * x0;
            x1 = t;
        }
        
        if (x1 < 0) x1 += m0;
        
        return x1;
    }
}
