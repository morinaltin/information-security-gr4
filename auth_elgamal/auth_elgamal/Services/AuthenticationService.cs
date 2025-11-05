using System.Security.Cryptography;
using auth_elgamal.Models;
using auth_elgamal.Storage;

namespace auth_elgamal.Services;

public class AuthenticationService
{
    private readonly IUserStorage _userStorage;
    private readonly AuthSettings _settings;

    private readonly Dictionary<string, AuthChallenge> _activeChallenges = new();
    private readonly Dictionary<string, string> _sessions = new();
    private readonly object _lock = new();

    public AuthenticationService(IUserStorage userStorage, AuthSettings? settings = null)
    {
        _userStorage = userStorage;
        _settings = settings ?? new AuthSettings();
    }

    public RegistrationResponse Register(RegistrationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Username))
            return new RegistrationResponse(false, "Username cannot be empty");

        if (string.IsNullOrWhiteSpace(request.Password))
            return new RegistrationResponse(false, "Password cannot be empty");

        if (_userStorage.UserExists(request.Username))
            return new RegistrationResponse(false, "Username already exists");

        var user = new User(request.Username, request.Password, request.PublicKey);
        bool ok = _userStorage.AddUser(user);
        return ok
            ? new RegistrationResponse(true, "Registration successful")
            : new RegistrationResponse(false, "Registration failed");
    }
    
    public AuthChallenge? GenerateChallenge(string username, TimeSpan? ttl = null)
    {
        if (!_userStorage.UserExists(username))
            return null;

        string challengeId = Guid.NewGuid().ToString();
        string message = GenerateRandomChallengeMessage();
        var effectiveTtl = ttl ?? _settings.ChallengeTtl;
        DateTime expiresAt = DateTime.UtcNow.Add(effectiveTtl);

        var challenge = new AuthChallenge(challengeId, message, expiresAt);

        lock (_lock)
        {
            _activeChallenges[challengeId] = challenge;
        }

        return challenge;
    }
    private static string GenerateRandomChallengeMessage()
    {
        byte[] bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes);
    }
    public AuthResponse Authenticate(AuthRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Username))
            return new AuthResponse(false, "Invalid username");

        AuthChallenge? challenge;
        lock (_lock)
        {
            _activeChallenges.TryGetValue(request.ChallengeId, out challenge);
        }
        if (challenge is null)
            return new AuthResponse(false, "Invalid challenge");

        if (challenge.IsExpired())
        {
            lock (_lock)
            {
                _activeChallenges.Remove(request.ChallengeId);
            }
            return new AuthResponse(false, "Challenge expired");
        }

        var user = _userStorage.GetUser(request.Username);
        if (user is null)
            return new AuthResponse(false, "User not found");

        bool ok = ElGamalSignatureOps.Verify(challenge.Message, request.Signature, user.PublicKey);
        if (!ok)
            return new AuthResponse(false, "Invalid signature");

        lock (_lock)
        {
            _activeChallenges.Remove(request.ChallengeId);
        }

        string sessionToken = Guid.NewGuid().ToString();
        lock (_lock)
        {
            _sessions[sessionToken] = request.Username;
        }
        _userStorage.UpdateLastLogin(request.Username);

        return new AuthResponse(true, "Authentication successful", sessionToken);
    }

    public bool IsValidSession(string sessionToken)
    {
        lock (_lock)
        {
            return _sessions.ContainsKey(sessionToken);
        }
    }

    public string? GetUsernameFromSession(string sessionToken)
    {
        lock (_lock)
        {
            return _sessions.GetValueOrDefault(sessionToken);
        }
    }

    public bool RevokeSession(string sessionToken)
    {
        lock (_lock)
        {
            return _sessions.Remove(sessionToken);
        }
    }
}
