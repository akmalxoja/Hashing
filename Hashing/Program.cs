using System;
using Npgsql;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static string connectionString = "Host=localhost;Username=postgres;Password=psqlDB;Database=connected";

    static void Main()
    {
        using (NpgsqlConnection conn = new NpgsqlConnection(connectionString))
        {
            conn.Open();

            Console.Write("Enter username: ");
            string username = Console.ReadLine();
            Console.Write("Enter password: ");
            string password = Console.ReadLine();
            string hashedPassword = HashPassword(password);

            RegisterUser(conn, username, hashedPassword);

            Console.Write("Enter recipient username: ");
            string recipient = Console.ReadLine();
            Console.Write("Enter message: ");
            string message = Console.ReadLine();

            SendMessage(conn, username, recipient, message);

            var messages = GetMessages(conn, username);
            Console.WriteLine("Messages received:");
            foreach (var msg in messages)
            {
                Console.WriteLine($"From {msg.sender}: {msg.message}");
            }
        }
    }

    static string HashPassword(string password)
    {
        byte[] salt = GenerateSalt();
        byte[] hash = ComputeHash(Encoding.UTF8.GetBytes(password), salt);
        return Convert.ToBase64String(salt) + "|" + Convert.ToBase64String(hash);
    }

    static byte[] GenerateSalt(int size = 16)
    {
        using (var rng = new RNGCryptoServiceProvider())
        {
            var salt = new byte[size];
            rng.GetBytes(salt);
            return salt;
        }
    }

    static byte[] ComputeHash(byte[] input, byte[] salt)
    {
        using (var pbkdf2 = new Rfc2898DeriveBytes(input, salt, 10000, HashAlgorithmName.SHA256))
        {
            return pbkdf2.GetBytes(32);
        }
    }

    static void RegisterUser(NpgsqlConnection conn, string username, string hashedPassword)
    {
        using (var cmd = new NpgsqlCommand())
        {
            cmd.Connection = conn;
            cmd.CommandText = "INSERT INTO users (username, password) VALUES (@username, @password)";
            cmd.Parameters.AddWithValue("username", username);
            cmd.Parameters.AddWithValue("password", hashedPassword);
            cmd.ExecuteNonQuery();
            Console.WriteLine("User registered successfully.");
        }
    }

    static void SendMessage(NpgsqlConnection conn, string sender, string recipient, string message)
    {
        using (var cmd = new NpgsqlCommand())
        {
            cmd.Connection = conn;
            cmd.CommandText = "INSERT INTO messages (sender, recipient, message) VALUES (@sender, @recipient, @message)";
            cmd.Parameters.AddWithValue("sender", sender);
            cmd.Parameters.AddWithValue("recipient", recipient);
            cmd.Parameters.AddWithValue("message", message);
            cmd.ExecuteNonQuery();
            Console.WriteLine("Message sent successfully.");
        }
    }

    static (string sender, string message)[] GetMessages(NpgsqlConnection conn, string username)
    {
        using (var cmd = new NpgsqlCommand())
        {
            cmd.Connection = conn;
            cmd.CommandText = "SELECT sender, message FROM messages WHERE recipient = @username";
            cmd.Parameters.AddWithValue("username", username);
            using (var reader = cmd.ExecuteReader())
            {
                var messages = new System.Collections.Generic.List<(string sender, string message)>();
                while (reader.Read())
                {
                    messages.Add((reader.GetString(0), reader.GetString(1)));
                }
                return messages.ToArray();
            }
        }
    }
}

