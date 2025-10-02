using auth_elgamal;

Console.WriteLine("=== ElGamal Authentication System - Day 1 ===");
Console.WriteLine("Testing: Key Generation\n");

var keyPair = ElGamalKeyGeneration.GenerateKeyPair(512);

Console.WriteLine("\n" + keyPair.PublicKey);
Console.WriteLine(keyPair.PrivateKey);
Console.WriteLine("\n✓ Day 1 Complete: Key generation working!");
