
using System.Security.Cryptography;
using System.Text;

namespace CajaFuerte;

internal static class CajaFuerteService
{
    
    public static void EncryptFile(string inputPath, string outputPath, string password)
    {
        
        byte[] plaintext = File.ReadAllBytes(inputPath);
        byte[] salt  = RandomNumberGenerator.GetBytes(FileFormat.SaltSize);
        byte[] nonce = RandomNumberGenerator.GetBytes(FileFormat.NonceSize);
        byte[] key = DeriveKey(password, salt);

        try
        {
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag        = new byte[FileFormat.TagSize];

            using (var aesGcm = new AesGcm(key, FileFormat.TagSize))
            {
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            using var fs     = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);
            using var writer = new BinaryWriter(fs, Encoding.UTF8, leaveOpen: false);

            writer.Write(FileFormat.Magic);   
            writer.Write(FileFormat.Version);  
            writer.Write(salt);                
            writer.Write(nonce);               
            writer.Write(tag);                 
            writer.Write(ciphertext);          
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static byte[] DeriveKey(string password, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            password: password,
            salt: salt,
            iterations: FileFormat.Pbkdf2Iterations,
            hashAlgorithm: HashAlgorithmName.SHA256,
            outputLength: FileFormat.KeySize);
    }
}