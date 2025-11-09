using auth_elgamal;

namespace auth_elgamal.Models;

public record RegistrationRequest(string Username, string Password, ElGamalPublicKey PublicKey);

public record RegistrationResponse(bool Success, string Message, RegistrationErrorCode Code = RegistrationErrorCode.None);
