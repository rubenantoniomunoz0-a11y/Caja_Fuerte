
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

     public static void DecryptFile(string inputPath, string outputPath, string password)
    {
        byte[] fileBytes = File.ReadAllBytes(inputPath);

        if (fileBytes.Length < FileFormat.HeaderSize)
            throw new CryptographicException("El fichero es demasiado pequeño.");

        for (int i = 0; i < FileFormat.MagicSize; i++)
        {
            if (fileBytes[FileFormat.OffsetMagic + i] != FileFormat.Magic[i])
                throw new CryptographicException("Cabecera inválida: no es un fichero .caja.");
        }

        if (fileBytes[FileFormat.OffsetVersion] != FileFormat.Version)
            throw new CryptographicException($"Versión no soportada: {fileBytes[FileFormat.OffsetVersion]}.");

        byte[] salt  = new byte[FileFormat.SaltSize];
        byte[] nonce = new byte[FileFormat.NonceSize];
        byte[] tag   = new byte[FileFormat.TagSize];

        int cipherLength  = fileBytes.Length - FileFormat.HeaderSize;
        byte[] ciphertext = new byte[cipherLength];

        Buffer.BlockCopy(fileBytes, FileFormat.OffsetSalt,   salt,       0, FileFormat.SaltSize);
        Buffer.BlockCopy(fileBytes, FileFormat.OffsetNonce,  nonce,      0, FileFormat.NonceSize);
        Buffer.BlockCopy(fileBytes, FileFormat.OffsetTag,    tag,        0, FileFormat.TagSize);
        Buffer.BlockCopy(fileBytes, FileFormat.OffsetCipher, ciphertext, 0, cipherLength);

        byte[] key = DeriveKey(password, salt);
        byte[] plaintext = new byte[cipherLength];

        try
        {
            using var aesGcm = new AesGcm(key, FileFormat.TagSize);
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
        }
        catch (CryptographicException)
        {
            throw new CryptographicException(
                "Verificación de integridad fallida: fichero manipulado o contraseña incorrecta.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        File.WriteAllBytes(outputPath, plaintext);
    }
}