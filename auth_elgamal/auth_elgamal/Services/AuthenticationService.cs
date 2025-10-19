using auth_elgamal.Models;
using auth_elgamal.Storage;

namespace auth_elgamal.Services;

/// <summary>
/// Authentication service (Day 8: registration only)
/// </summary>
public class AuthenticationService
{
    private readonly IUserStorage _userStorage;

    public AuthenticationService(IUserStorage userStorage)
    {
        _userStorage = userStorage;
    }

    /// <summary>
    /// Register a new user by storing username, password hash, and ElGamal public key
    /// </summary>
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
}
