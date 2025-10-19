using auth_elgamal;

namespace auth_elgamal.Models;

/// <summary>
/// Registration request carrying username, password and user's ElGamal public key
/// </summary>
public record RegistrationRequest(string Username, string Password, ElGamalPublicKey PublicKey);

/// <summary>
/// Registration response indicating success/failure and a message
/// </summary>
public record RegistrationResponse(bool Success, string Message);
