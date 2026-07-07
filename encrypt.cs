using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class FileEncryptor
{
    // Derive a 256-bit AES key and 128-bit IV from the Secret Key (SK) and a salt
    private static void DeriveKeyAndIV(string sk, byte[] salt, out byte[] key, out byte[] iv)
    {
        using var deriveBytes = new Rfc2898DeriveBytes(sk, salt, 10000, HashAlgorithmName.SHA256);
        key = deriveBytes.GetBytes(32); // 32 bytes for AES-256
        iv = deriveBytes.GetBytes(16);  // 16 bytes for AES IV
    }

    public static void EncryptFile(string inputFile, string outputFile, string sk)
    {
        // Generate a random salt for added security
        byte[] salt = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(salt);

        DeriveKeyAndIV(sk, salt, out byte[] key, out byte[] iv);

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;

        using var inputFileStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read);
        using var outputFileStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write);

        // Write the salt to the beginning of the file so it's available for decryption
        outputFileStream.Write(salt, 0, salt.Length);

        using var encryptor = aes.CreateEncryptor();
        using var cryptoStream = new CryptoStream(outputFileStream, encryptor, CryptoStreamMode.Write);

        // Copy the file contents to the CryptoStream
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = inputFileStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            cryptoStream.Write(buffer, 0, bytesRead);
        }
        
        // Clear sensitive data
        Array.Clear(key, 0, key.Length);
        Array.Clear(iv, 0, iv.Length);
    }
}
