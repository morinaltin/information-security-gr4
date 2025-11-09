namespace auth_elgamal.Models;
public enum AuthErrorCode
{
    None = 0,
    InvalidUsername,
    InvalidChallenge,
    ChallengeExpired,
    UserNotFound,
    InvalidSignature,
}

public enum RegistrationErrorCode
{
    None = 0,
    UsernameEmpty,
    PasswordEmpty,
    UserExists,
    PersistFailed,
}
