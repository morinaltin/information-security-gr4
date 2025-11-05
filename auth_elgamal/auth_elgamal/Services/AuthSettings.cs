namespace auth_elgamal.Services;

public class AuthSettings
{

    public TimeSpan ChallengeTtl { get; init; } = TimeSpan.FromMinutes(5);
    public int DefaultKeySizeBits { get; init; } = 512;
}
