using auth_elgamal;
using auth_elgamal.Client;
using auth_elgamal.Services;
using auth_elgamal.Storage;

Console.WriteLine("=== Day 16: End-to-end demo with configurable settings ===\n");

var storage = new InMemoryUserStorage();
var settings = new AuthSettings { ChallengeTtl = TimeSpan.FromMinutes(2), DefaultKeySizeBits = 512 };
var service = new AuthenticationService(storage, settings, new ConsoleAuthLogger());

var client = new AuthenticationClient(service);

var register = client.Register("alice", "password123", 512);
Console.WriteLine($"Register -> Success: {register.Success}, Code: {register.Code}, Message: {register.Message}");

var login = client.Login("alice");
Console.WriteLine($"Login -> Success: {login.Success}, Code: {login.Code}, Message: {login.Message}");

if (login.Success)
{
    var token = client.GetSessionToken();
    Console.WriteLine($"Session token: {token}");

    Console.WriteLine($"Session valid? {service.IsValidSession(token!)}");
    Console.WriteLine($"Session user: {service.GetUsernameFromSession(token!)}");
}