using System.Security.Cryptography;
using auth_elgamal.Models;
using auth_elgamal.Storage;

namespace auth_elgamal.Services;

public class AuthenticationService
{
    private readonly IUserStorage _userStorage;
private readonly AuthSettings _settings;
    private readonly IAuthLogger _logger;

    private readonly Dictionary<string, AuthChallenge> _activeChallenges = new();
    private readonly Dictionary<string, string> _sessions = new();
    private readonly object _lock = new();

public AuthenticationService(IUserStorage userStorage, AuthSettings? settings = null, IAuthLogger? logger = null)
    {
        _userStorage = userStorage;
        _settings = settings ?? new AuthSettings();
        _logger = logger ?? new NoopAuthLogger();
    }

public RegistrationResponse Register(RegistrationRequest request)
    {
        _logger.Info($"Register attempt: {request.Username}");

        if (string.IsNullOrWhiteSpace(request.Username))
            return new RegistrationResponse(false, "Username cannot be empty", RegistrationErrorCode.UsernameEmpty);

        if (string.IsNullOrWhiteSpace(request.Password))
            return new RegistrationResponse(false, "Password cannot be empty", RegistrationErrorCode.PasswordEmpty);

        if (_userStorage.UserExists(request.Username))
        {
            _logger.Warn($"Register failed: username exists - {request.Username}");
            return new RegistrationResponse(false, "Username already exists", RegistrationErrorCode.UserExists);
        }

        var user = new User(request.Username, request.Password, request.PublicKey);
        bool ok = _userStorage.AddUser(user);
        if (ok)
        {
            _logger.Info($"Register success: {request.Username}");
            return new RegistrationResponse(true, "Registration successful", RegistrationErrorCode.None);
        }
        else
        {
            _logger.Error($"Register failed to persist: {request.Username}");
            return new RegistrationResponse(false, "Registration failed", RegistrationErrorCode.PersistFailed);
        }
    }
    
public AuthChallenge? GenerateChallenge(string username, TimeSpan? ttl = null)
    {
        _logger.Info($"GenerateChallenge for: {username}");
        if (!_userStorage.UserExists(username))
        {
            _logger.Warn($"GenerateChallenge failed: user not found - {username}");
            return null;
        }

        string challengeId = Guid.NewGuid().ToString();
        string message = GenerateRandomChallengeMessage();
        var effectiveTtl = ttl ?? _settings.ChallengeTtl;
        DateTime expiresAt = DateTime.UtcNow.Add(effectiveTtl);

        var challenge = new AuthChallenge(challengeId, message, expiresAt);

        lock (_lock)
        {
            _activeChallenges[challengeId] = challenge;
        }

        _logger.Info($"Challenge issued: {challengeId}, expires {expiresAt:O}");
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
        _logger.Info($"Authenticate attempt: {request.Username}");
        if (string.IsNullOrWhiteSpace(request.Username))
            return new AuthResponse(false, "Invalid username", null, AuthErrorCode.InvalidUsername);

        AuthChallenge? challenge;
        lock (_lock)
        {
            _activeChallenges.TryGetValue(request.ChallengeId, out challenge);
        }
        if (challenge is null)
        {
            _logger.Warn($"Authenticate failed: invalid challenge for {request.Username}");
            return new AuthResponse(false, "Invalid challenge", null, AuthErrorCode.InvalidChallenge);
        }

        if (challenge.IsExpired())
        {
            lock (_lock)
            {
                _activeChallenges.Remove(request.ChallengeId);
            }
            _logger.Warn($"Authenticate failed: expired challenge {request.ChallengeId} for {request.Username}");
            return new AuthResponse(false, "Challenge expired", null, AuthErrorCode.ChallengeExpired);
        }

        var user = _userStorage.GetUser(request.Username);
        if (user is null)
        {
            _logger.Warn($"Authenticate failed: user not found - {request.Username}");
            return new AuthResponse(false, "User not found", null, AuthErrorCode.UserNotFound);
        }

        bool ok = ElGamalSignatureOps.Verify(challenge.Message, request.Signature, user.PublicKey);
        if (!ok)
        {
            _logger.Warn($"Authenticate failed: invalid signature for {request.Username}");
            return new AuthResponse(false, "Invalid signature", null, AuthErrorCode.InvalidSignature);
        }

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
        _logger.Info($"Authenticate success: session issued for {request.Username}");

        return new AuthResponse(true, "Authentication successful", sessionToken, AuthErrorCode.None);
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
            var removed = _sessions.Remove(sessionToken);
            if (removed) _logger.Info($"Session revoked: {sessionToken}");
            else _logger.Warn($"RevokeSession: token not found");
            return removed;
        }
    }
}
