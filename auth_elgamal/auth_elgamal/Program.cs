using auth_elgamal;
using auth_elgamal.Client;
using auth_elgamal.Services;
using auth_elgamal.Storage;

Console.WriteLine("=== Day 14: End-to-end registration and login demo ===\n");

var storage = new InMemoryUserStorage();
var service = new AuthenticationService(storage);

var client = new AuthenticationClient(service);

var register = client.Register("alice", "password123", 512);
Console.WriteLine($"Register -> Success: {register.Success}, Message: {register.Message}");

var login = client.Login("alice");
Console.WriteLine($"Login -> Success: {login.Success}, Message: {login.Message}");

if (login.Success)
{
    var token = client.GetSessionToken();
    Console.WriteLine($"Session token: {token}");

    Console.WriteLine($"Session valid? {service.IsValidSession(token!)}");
    Console.WriteLine($"Session user: {service.GetUsernameFromSession(token!)}");
}

Console.WriteLine("\n✓ Day 14 complete");
