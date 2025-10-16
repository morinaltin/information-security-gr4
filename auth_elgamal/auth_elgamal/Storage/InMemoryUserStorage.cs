using auth_elgamal.Models;

namespace auth_elgamal.Storage;

public class InMemoryUserStorage : IUserStorage
{
    private readonly Dictionary<string, User> _users = new();
    private readonly object _lock = new();

    public bool AddUser(User user)
    {
        lock (_lock)
        {
            if (_users.ContainsKey(user.Username)) return false;
            _users[user.Username] = user;
            return true;
        }
    }

    public User? GetUser(string username)
    {
        lock (_lock)
        {
            _users.TryGetValue(username, out var user);
            return user;
        }
    }

    public bool UserExists(string username)
    {
        lock (_lock)
        {
            return _users.ContainsKey(username);
        }
    }

    public IEnumerable<User> GetAllUsers()
    {
        lock (_lock)
        {
            return _users.Values.ToList();
        }
    }

    public void UpdateLastLogin(string username)
    {
        lock (_lock)
        {
            if (_users.TryGetValue(username, out var user))
            {
                user.LastLoginAt = DateTime.UtcNow;
            }
        }
    }
}
