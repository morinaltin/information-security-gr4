using auth_elgamal.Models;

namespace auth_elgamal.Storage;

public interface IUserStorage
{
    bool AddUser(User user);
    
    User? GetUser(string username);
    
    bool UserExists(string username);
    
    IEnumerable<User> GetAllUsers();
    
    void UpdateLastLogin(string username);
}
