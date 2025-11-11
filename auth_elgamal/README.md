# ElGamal Authentication System

A cryptographic authentication system that implements passwordless authentication using **ElGamal digital signatures** and a challenge-response protocol. This project demonstrates how to build a secure authentication system without transmitting passwords during login.

## 🎯 Overview

This C# application provides a complete authentication framework where users authenticate by proving possession of a private key through digital signatures. Instead of sending passwords, users sign server-generated challenges, providing strong cryptographic authentication.

## ✨ Features

- **ElGamal Digital Signatures**: Full implementation of ElGamal signature generation and verification
- **Challenge-Response Protocol**: Time-limited challenges prevent replay attacks
- **Passwordless Authentication**: No password transmission during login
- **Session Management**: Secure session token generation and validation
- **Configurable Security**: Adjustable key sizes and challenge TTL
- **Thread-Safe Operations**: All storage and authentication operations are thread-safe
- **Key Serialization**: Support for exporting/importing public keys in JSON format

## 🏗️ Architecture

### Core Components

1. **ElGamal Cryptography** (`ElGamalKeyGeneration.cs`, `ElGamalSignature.cs`)
   - Prime number generation using Miller-Rabin primality test
   - ElGamal key pair generation (public/private keys)
   - Message signing and signature verification
   - SHA-256 hashing for message digest

2. **Authentication Service** (`AuthenticationService.cs`)
   - User registration with public key storage
   - Challenge generation with expiration
   - Signature verification and authentication
   - Session token management

3. **Client Library** (`AuthenticationClient.cs`)
   - Simplified API for registration and login
   - Automatic key pair management
   - Challenge signing automation

4. **Storage Layer** (`InMemoryUserStorage.cs`)
   - In-memory user storage (can be extended to database)
   - Thread-safe user operations

## 📋 Prerequisites

- .NET 9.0 SDK or later
- Windows, Linux, or macOS

## 🚀 Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd auth_elgamal
```

2. Restore dependencies:
```bash
dotnet restore
```

3. Build the project:
```bash
dotnet build
```

4. Run the demo:
```bash
dotnet run --project auth_elgamal
```

## 💻 Usage

### Basic Example

```csharp
using auth_elgamal;
using auth_elgamal.Client;
using auth_elgamal.Services;
using auth_elgamal.Storage;

// Setup
var storage = new InMemoryUserStorage();
var settings = new AuthSettings 
{ 
    ChallengeTtl = TimeSpan.FromMinutes(2), 
    DefaultKeySizeBits = 512 
};
var service = new AuthenticationService(storage, settings);
var client = new AuthenticationClient(service);

// Register a new user
var register = client.Register("alice", "password123", 512);
Console.WriteLine($"Register: {register.Success} - {register.Message}");

// Login
var login = client.Login("alice");
Console.WriteLine($"Login: {login.Success} - {login.Message}");

if (login.Success)
{
    var token = client.GetSessionToken();
    Console.WriteLine($"Session token: {token}");
    
    // Validate session
    bool isValid = service.IsValidSession(token!);
    string? username = service.GetUsernameFromSession(token!);
    Console.WriteLine($"Session valid: {isValid}, User: {username}");
}
```

### Advanced Configuration

```csharp
var settings = new AuthSettings
{
    ChallengeTtl = TimeSpan.FromMinutes(5),  // Challenge expiration time
    DefaultKeySizeBits = 2048                // Key size in bits (512, 1024, 2048, etc.)
};

var service = new AuthenticationService(storage, settings, new ConsoleAuthLogger());
```

## 🔐 Authentication Flow

### 1. Registration
```
Client                          Server
  |                               |
  |-- Generate ElGamal Key Pair --|
  |                               |
  |-- Register(username,        -->|
  |    password, publicKey)        |
  |                               |-- Store user with:
  |                               |   - Username
  |                               |   - Password hash (SHA-256)
  |                               |   - Public key
  |<-- Registration Response -----|
  |                               |
```

### 2. Login (Challenge-Response)
```
Client                          Server
  |                               |
  |-- Request Challenge(username) -->|
  |                               |-- Generate random challenge
  |                               |-- Store challenge with TTL
  |<-- Challenge (message, id) ---|
  |                               |
  |-- Sign challenge with         |
  |   private key                 |
  |                               |
  |-- Authenticate(username,     -->|
  |    challengeId, signature)     |
  |                               |-- Verify signature using
  |                               |   stored public key
  |                               |-- Check challenge expiration
  |<-- Auth Response +            |
  |    Session Token -------------|
  |                               |
```

### 3. Session Validation
```
Client                          Server
  |                               |
  |-- Validate Session(token) ---->|
  |                               |-- Check token exists
  |                               |-- Return username
  |<-- Session Status +           |
  |    Username ------------------|
  |                               |
```

## 🔒 Security Features

- **Cryptographic Authentication**: Uses ElGamal digital signatures (asymmetric cryptography)
- **Challenge-Response Protocol**: Prevents replay attacks with time-limited challenges
- **No Password Transmission**: Passwords are only used during registration, never sent during login
- **Secure Hashing**: SHA-256 for password hashing and message digest
- **Thread Safety**: All operations are protected with locks
- **Configurable TTL**: Challenge expiration prevents stale authentication attempts

## 📁 Project Structure

```
auth_elgamal/
├── Client/
│   └── AuthenticationClient.cs      # High-level client API
├── Models/
│   ├── AuthModels.cs                # Authentication request/response models
│   ├── RegistrationModels.cs        # Registration models
│   ├── User.cs                      # User entity
│   └── ErrorCodes.cs                # Error code enumerations
├── Services/
│   ├── AuthenticationService.cs     # Core authentication logic
│   ├── AuthSettings.cs              # Configuration settings
│   └── Logging.cs                   # Logging interface
├── Storage/
│   ├── IUserStorage.cs              # Storage interface
│   └── InMemoryUserStorage.cs      # In-memory implementation
├── ElGamalKeyGeneration.cs          # Key pair generation
├── ElGamalSignature.cs              # Signing and verification
├── KeySerialization.cs              # Key export/import utilities
└── Program.cs                        # Demo application
```

## 🔧 Technical Details

### ElGamal Signature Scheme

The implementation follows the standard ElGamal signature algorithm:

1. **Key Generation**:
   - Generate large prime `p`
   - Find generator `g` of the multiplicative group
   - Choose private key `x` randomly
   - Compute public key `y = g^x mod p`

2. **Signing**:
   - Hash message to get `h`
   - Choose random `k` coprime to `p-1`
   - Compute `r = g^k mod p`
   - Compute `s = (h - x*r) * k^(-1) mod (p-1)`
   - Signature is `(r, s)`

3. **Verification**:
   - Hash message to get `h`
   - Verify: `g^h ≡ y^r * r^s (mod p)`

### Key Sizes

- **512 bits**: Fast, suitable for development/testing
- **1024 bits**: Moderate security
- **2048 bits**: Recommended for production (slower key generation)

## 🧪 Testing

The project includes a demo in `Program.cs` that demonstrates:
- User registration
- Challenge generation
- Authentication flow
- Session management

Run the demo:
```bash
dotnet run --project auth_elgamal
```

## 📝 Notes

- This is an **educational project** demonstrating cryptographic authentication
- The in-memory storage is for demonstration; production systems should use persistent storage
- Key generation can be slow for large key sizes (2048+ bits)
- The current implementation uses a fixed generator (g=2) for simplicity

## 🔮 Future Enhancements

- [ ] Database-backed user storage
- [ ] Key rotation support
- [ ] Multi-factor authentication
- [ ] API endpoints (REST/GraphQL)
- [ ] Key recovery mechanisms
- [ ] Rate limiting for challenges
- [ ] Audit logging

## 📚 References

- [ElGamal Signature Scheme](https://en.wikipedia.org/wiki/ElGamal_signature_scheme)
- [Miller-Rabin Primality Test](https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test)
- [Challenge-Response Authentication](https://en.wikipedia.org/wiki/Challenge%E2%80%93response_authentication)

## 📄 License

This project is for educational purposes as part of an information security course.

---

**Note**: This implementation is for educational demonstration. For production use, consider using established cryptographic libraries and security best practices.

