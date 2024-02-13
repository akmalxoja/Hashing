using System.Security.Cryptography;
using System.Text;

namespace Hashing
{
    public class Program
    {
        private static void Main(string[] args)
        {
            // hash algorithms are one-way, determenistic.
            string user1Password = "12345678";

            // rainbow table
            byte[] user1PasswordAsByte = Encoding.UTF8.GetBytes(user1Password);

            int iterations = 350_000;
            int keySize = 64;
            var hashAlgorithm = HashAlgorithmName.SHA512;

            bool isUser1PasswordValid = ValidatePassword(
                passwordFromUser: "user1_google",
                hashFromDB: "FDA309652336DFD0E302AC298E92E5FFE1F3F2EC5DA9D3D632C817982762447AF948B45DE88BBF1F9FDAD51DFFCE970E91AA8C856FF1980575EA4394888D043E",
                saltAsStringFromDB: "84F232562DE718D187F6456E60CC39E5A080A70C6CA8E988BD1924CE6CD98DB2E1E28B55CB15C3C77EF62A925F6BCEA64EA7F94ECB9234599177ACDE28A527A2",
                keySize,
                iterations,
                hashAlgorithm
                );

            Console.WriteLine(isUser1PasswordValid);
        }
        // in, ref, out  -> ref birinchi ref yaratilgan,
        private static string HashData(string password, int keySize, int iterations, HashAlgorithmName hashAlgorithm, out byte[] salt)
        {
            salt = RandomNumberGenerator.GetBytes(keySize);

            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                iterations,
                hashAlgorithm,
                outputLength: keySize);

            return Convert.ToHexString(hash);
        }

        private static string HashStringAndReturnSHA512AsHexString(string password)
        {
            byte[] passwordAsBytes = Encoding.UTF8.GetBytes(password);

            byte[] hash = SHA512.HashData(passwordAsBytes);

            return Convert.ToHexString(hash);
        }

        private static bool ValidatePassword(
            string passwordFromUser,
            string hashFromDB,
            string saltAsStringFromDB,
            int keySizeFromProgram,
            int iterationsFromProgram,
            HashAlgorithmName hashAlgorithmFromProgram)
        {
            // 84 F2 32 56 -> (0, 1, 2, 3, 4, 5, 6, 7) -> Where (0, 2, 4, 6) -> Select [84, F2, 32, 56]
            //byte[] salt = Enumerable.Range(0, saltAsString.Length)
            	//			.Where(x => x % 2 == 0)
            		//		.Select(x => Convert.ToByte(saltAsString.Substring(x, 2)))
            			//	.ToArray();

            byte[] salt = Convert.FromHexString(saltAsStringFromDB);

            var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(
                password: passwordFromUser,
                salt,
                iterations: iterationsFromProgram,
                hashAlgorithm: hashAlgorithmFromProgram,
                outputLength: keySizeFromProgram);

            return CryptographicOperations.FixedTimeEquals(hashToCompare, Convert.FromHexString(hashFromDB));
        }
    }
}