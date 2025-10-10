using System;

namespace auth_elgamal.Models;

public record AuthChallenge(string ChallengeId, string Message, DateTime ExpiresAt)
{
    public bool IsExpired() => DateTime.UtcNow > ExpiresAt;
}

public record AuthRequest(string Username, string ChallengeId, auth_elgamal.ElGamalSignature Signature);


public record AuthResponse(bool Success, string Message, string? SessionToken = null);
