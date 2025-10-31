using auth_elgamal;
using auth_elgamal.Models;
using auth_elgamal.Services;

namespace auth_elgamal.Client;

public class AuthenticationClient
{
    private readonly AuthenticationService _authService;

    private ElGamalKeyPair? _keyPair;
    private string? _username;
    private string? _sessionToken;

    public string? Username => _username;
    public bool HasKeys => _keyPair is not null;
    public ElGamalPublicKey? PublicKey => _keyPair?.PublicKey;
    public bool IsAuthenticated => !string.IsNullOrEmpty(_sessionToken);

    public AuthenticationClient(AuthenticationService authService)
    {
        _authService = authService;
    }

    public RegistrationResponse Register(string username, string password, int keySizeBits = 512)
    {
        _username = username;

        _keyPair = ElGamalKeyGeneration.GenerateKeyPair(keySizeBits);

        var req = new RegistrationRequest(username, password, _keyPair.PublicKey);
        var resp = _authService.Register(req);

        if (!resp.Success)
        {
            _username = null;
            _keyPair = null;
        }
        return resp;
    }

    public AuthResponse Login(string username)
    {
        if (_keyPair is null)
            return new AuthResponse(false, "No keys available on client");

        _username = username;

        var challenge = _authService.GenerateChallenge(username);
        if (challenge is null)
            return new AuthResponse(false, "Failed to get challenge");

        var signature = ElGamalSignatureOps.Sign(challenge.Message, _keyPair);

        var authReq = new AuthRequest(username, challenge.ChallengeId, signature);
        var resp = _authService.Authenticate(authReq);

        if (resp.Success)
        {
            _sessionToken = resp.SessionToken;
        }
        return resp;
    }

    public ElGamalKeyPair? GetKeyPair() => _keyPair;
    public string? GetSessionToken() => _sessionToken;
}
