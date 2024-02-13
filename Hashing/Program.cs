using System;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        
        string userPassword = "FoydalanuvchiParoli";

       
        string salt = GenerateSalt();


        
        string saltedPassword = userPassword + salt;

        
        string hashedPassword = HashPassword(saltedPassword);

        
        Console.WriteLine($"Parol: {userPassword}");
        Console.WriteLine($"Salt: {salt}");
        Console.WriteLine($"Hashlangan parol: {hashedPassword}");
    }

    static string GenerateSalt()
    {
        
        byte[] randomBytes = new byte[32];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomBytes);
        }

      
        string salt = Convert.ToBase64String(randomBytes);

        return salt;
    }

    static string HashPassword(string password)
    {
       
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(hashedBytes);
        }
    }
}
