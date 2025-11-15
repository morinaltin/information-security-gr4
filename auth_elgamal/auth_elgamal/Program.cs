using auth_elgamal;
using auth_elgamal.Models;
using auth_elgamal.Services;
using auth_elgamal.Storage;
using System.Collections.Concurrent;

Console.WriteLine("=== ElGamal Authentication System ===\n");

var storage = new InMemoryUserStorage();
var settings = new AuthSettings { ChallengeTtl = TimeSpan.FromMinutes(2), DefaultKeySizeBits = 512 };
var service = new AuthenticationService(storage, settings, new ConsoleAuthLogger());

var keyPairStorage = new ConcurrentDictionary<string, ElGamalKeyPair>();

bool running = true;
while (running)
{
    Console.WriteLine("\n=== Main Menu ===");
    Console.WriteLine("1. Register");
    Console.WriteLine("2. Login");
    Console.WriteLine("3. Exit");
    Console.Write("\nSelect an option (1-3): ");
    
    var choice = Console.ReadLine()?.Trim();
    
    switch (choice)
    {
        case "1":
            HandleRegistration(storage, service, keyPairStorage);
            break;
        case "2":
            HandleLogin(storage, service, keyPairStorage);
            break;
        case "3":
            Console.WriteLine("\nExiting... Goodbye!");
            running = false;
            break;
        default:
            Console.WriteLine("\nInvalid option. Please select 1, 2, or 3.");
            break;
    }
}

static void HandleRegistration(InMemoryUserStorage storage, AuthenticationService service, ConcurrentDictionary<string, ElGamalKeyPair> keyPairStorage)
{
    Console.WriteLine("\n=== Registration ===");
    Console.Write("Enter username: ");
    var username = Console.ReadLine()?.Trim();
    
    if (string.IsNullOrWhiteSpace(username))
    {
        Console.WriteLine("Error: Username cannot be empty.");
        return;
    }
    
    if (storage.UserExists(username))
    {
        Console.WriteLine($"Error: Username '{username}' already exists.");
        return;
    }
    
    Console.Write("Enter password: ");
    var password = ReadPassword();
    
    if (string.IsNullOrWhiteSpace(password))
    {
        Console.WriteLine("Error: Password cannot be empty.");
        return;
    }
    
    Console.WriteLine("\nGenerating ElGamal key pair... This may take a moment...");
    var keyPair = ElGamalKeyGeneration.GenerateKeyPair(512);
    
    var request = new RegistrationRequest(username, password, keyPair.PublicKey);
    var response = service.Register(request);
    
    if (response.Success)
    {
        // Store the keypair in memory for later login
        keyPairStorage[username] = keyPair;
        Console.WriteLine($"\n✓ Registration successful! User '{username}' has been registered.");
    }
    else
    {
        Console.WriteLine($"\n✗ Registration failed: {response.Message}");
    }
}

static void HandleLogin(InMemoryUserStorage storage, AuthenticationService service, ConcurrentDictionary<string, ElGamalKeyPair> keyPairStorage)
{
    Console.WriteLine("\n=== Login ===");
    Console.Write("Enter username: ");
    var username = Console.ReadLine()?.Trim();
    
    if (string.IsNullOrWhiteSpace(username))
    {
        Console.WriteLine("Error: Username cannot be empty.");
        return;
    }
    
    var user = storage.GetUser(username);
    if (user == null)
    {
        Console.WriteLine($"Error: User '{username}' not found.");
        return;
    }
    
    Console.Write("Enter password: ");
    var password = ReadPassword();
    
    if (!user.VerifyPassword(password))
    {
        Console.WriteLine("\n✗ Authentication failed: Invalid password.");
        return;
    }
    
    if (!keyPairStorage.TryGetValue(username, out var keyPair))
    {
        Console.WriteLine("\n✗ Error: Key pair not found. Please register again.");
        return;
    }
    
    Console.WriteLine("\nInitiating ElGamal challenge-response authentication...");
    
    var challenge = service.GenerateChallenge(username);
    if (challenge == null)
    {
        Console.WriteLine("✗ Failed to generate challenge.");
        return;
    }
    
    var signature = ElGamalSignatureOps.Sign(challenge.Message, keyPair);
    var authRequest = new AuthRequest(username, challenge.ChallengeId, signature);
    var authResponse = service.Authenticate(authRequest);
    
    if (authResponse.Success)
    {
        Console.WriteLine($"\n✓ Login successful!");
        Console.WriteLine($"Session token: {authResponse.SessionToken}");
        Console.WriteLine($"Session valid: {service.IsValidSession(authResponse.SessionToken!)}");
        Console.WriteLine($"Logged in as: {service.GetUsernameFromSession(authResponse.SessionToken!)}");
    }
    else
    {
        Console.WriteLine($"\n✗ Login failed: {authResponse.Message}");
    }
}

static string ReadPassword()
{
    string password = "";
    ConsoleKeyInfo key;
    
    do
    {
        key = Console.ReadKey(true);
        
        if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
        {
            password += key.KeyChar;
            Console.Write("*");
        }
        else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
        {
            password = password[..^1];
            Console.Write("\b \b");
        }
    }
    while (key.Key != ConsoleKey.Enter);
    
    Console.WriteLine();
    return password;
}