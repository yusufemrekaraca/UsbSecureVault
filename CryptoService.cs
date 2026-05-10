using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO;

namespace UsbSecureVault;

public static class CryptoService
{
    public const int SaltSize = 16;
    public const int KeySize = 32;
    public const int NonceSize = 12;
    public const int TagSize = 16;
    private const int StreamingChunkSize = 4 * 1024 * 1024;
    private static readonly byte[] StreamingMagic = "USV2GCM1"u8.ToArray();

    public static byte[] RandomBytes(int length)
    {
        var bytes = new byte[length];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    public static string ToBase64(byte[] bytes) => Convert.ToBase64String(bytes);

    public static byte[] FromBase64(string value) => Convert.FromBase64String(value);

    public static byte[] DeriveKey(string password, byte[] salt, int iterations)
    {
        using var kdf = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
        return kdf.GetBytes(KeySize);
    }

    public static string PasswordVerifier(string password, byte[] salt, int iterations)
    {
        var key = DeriveKey(password, salt, iterations);
        return ToBase64(SHA256.HashData(key));
    }

    public static bool VerifyPassword(string password, string saltBase64, int iterations, string expectedHash)
    {
        var actual = PasswordVerifier(password, FromBase64(saltBase64), iterations);
        return FixedTimeEquals(actual, expectedHash);
    }

    public static EncryptedBlob EncryptBytes(byte[] key, byte[] plaintext, byte[]? associatedData = null)
    {
        var nonce = RandomBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        return new EncryptedBlob(ToBase64(nonce), ToBase64(tag), ToBase64(ciphertext));
    }

    public static byte[] DecryptBytes(byte[] key, EncryptedBlob blob, byte[]? associatedData = null)
    {
        var nonce = FromBase64(blob.Nonce);
        var tag = FromBase64(blob.Tag);
        var ciphertext = FromBase64(blob.Ciphertext);
        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }

    public static EncryptedBlob EncryptJson<T>(byte[] key, T value, byte[]? associatedData = null)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions.Default);
        return EncryptBytes(key, json, associatedData);
    }

    public static T DecryptJson<T>(byte[] key, EncryptedBlob blob, byte[]? associatedData = null)
    {
        var bytes = DecryptBytes(key, blob, associatedData);
        return JsonSerializer.Deserialize<T>(bytes, JsonOptions.Default)
               ?? throw new InvalidOperationException("Şifreli veri okunamadı.");
    }

    public static void EncryptFileInPlaceAndMove(byte[] key, string sourcePath, string destinationPath, out string nonceBase64, out string tagBase64)
    {
        var tempPath = Path.Combine(
            Path.GetDirectoryName(sourcePath)!,
            $".{Path.GetFileName(sourcePath)}.{Guid.NewGuid():N}.usvtmp");

        try
        {
            EncryptFileFromPathToPath(key, sourcePath, tempPath, out nonceBase64, out tagBase64);
            File.Delete(sourcePath);
            File.Move(tempPath, destinationPath);
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    public static void EncryptFileFromPathToPath(byte[] key, string sourcePath, string destinationPath, out string nonceBase64, out string tagBase64)
    {
        EncryptFileChunked(key, sourcePath, destinationPath);
        nonceBase64 = "";
        tagBase64 = "";
    }

    public static void DecryptFileToPath(byte[] key, FileRecord record, string encryptedPath, string destinationPath)
    {
        if (IsChunkedEncryptedFile(encryptedPath))
        {
            DecryptFileChunked(key, encryptedPath, destinationPath);
            return;
        }

        var ciphertext = File.ReadAllBytes(encryptedPath);
        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(FromBase64(record.ContentNonce), ciphertext, FromBase64(record.ContentTag), plaintext);
        File.WriteAllBytes(destinationPath, plaintext);
        CryptographicOperations.ZeroMemory(plaintext);
    }

    public static byte[] Utf8(string value) => Encoding.UTF8.GetBytes(value);

    private static bool FixedTimeEquals(string left, string right)
    {
        var a = Encoding.UTF8.GetBytes(left);
        var b = Encoding.UTF8.GetBytes(right);
        return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    }

    private static void EncryptFileChunked(byte[] key, string sourcePath, string destinationPath)
    {
        var noncePrefix = RandomBytes(4);
        var buffer = new byte[StreamingChunkSize];
        var ciphertext = new byte[StreamingChunkSize];
        using var input = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, StreamingChunkSize);
        using var output = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None, StreamingChunkSize);
        using var aes = new AesGcm(key, TagSize);
        var tag = new byte[TagSize];

        output.Write(StreamingMagic);
        output.Write(BitConverter.GetBytes(StreamingChunkSize));
        output.Write(noncePrefix);

        ulong chunkIndex = 0;
        int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
        {
            var nonce = BuildChunkNonce(noncePrefix, chunkIndex++);
            aes.Encrypt(nonce, buffer.AsSpan(0, read), ciphertext.AsSpan(0, read), tag);
            output.Write(BitConverter.GetBytes(read));
            output.Write(tag);
            output.Write(ciphertext, 0, read);
        }

        CryptographicOperations.ZeroMemory(buffer);
        CryptographicOperations.ZeroMemory(ciphertext);
        CryptographicOperations.ZeroMemory(tag);
    }

    private static void DecryptFileChunked(byte[] key, string encryptedPath, string destinationPath)
    {
        using var input = new FileStream(encryptedPath, FileMode.Open, FileAccess.Read, FileShare.Read, StreamingChunkSize);
        using var output = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None, StreamingChunkSize);

        var magic = new byte[StreamingMagic.Length];
        input.ReadExactly(magic);
        if (!magic.SequenceEqual(StreamingMagic))
        {
            throw new InvalidOperationException("Şifreli dosya biçimi okunamadı.");
        }

        var chunkSizeBytes = new byte[sizeof(int)];
        input.ReadExactly(chunkSizeBytes);
        var chunkSize = BitConverter.ToInt32(chunkSizeBytes);
        if (chunkSize <= 0 || chunkSize > 64 * 1024 * 1024)
        {
            throw new InvalidOperationException("Şifreli dosya parça boyutu geçersiz.");
        }

        var noncePrefix = new byte[4];
        input.ReadExactly(noncePrefix);
        var ciphertext = new byte[chunkSize];
        var plaintext = new byte[chunkSize];
        var lengthBytes = new byte[sizeof(int)];
        var tag = new byte[TagSize];
        using var aes = new AesGcm(key, TagSize);

        ulong chunkIndex = 0;
        while (input.Position < input.Length)
        {
            input.ReadExactly(lengthBytes);
            var length = BitConverter.ToInt32(lengthBytes);
            if (length <= 0 || length > chunkSize)
            {
                throw new InvalidOperationException("Şifreli dosya parçası geçersiz.");
            }

            input.ReadExactly(tag);
            input.ReadExactly(ciphertext.AsSpan(0, length));
            var nonce = BuildChunkNonce(noncePrefix, chunkIndex++);
            aes.Decrypt(nonce, ciphertext.AsSpan(0, length), tag, plaintext.AsSpan(0, length));
            output.Write(plaintext, 0, length);
        }

        CryptographicOperations.ZeroMemory(ciphertext);
        CryptographicOperations.ZeroMemory(plaintext);
    }

    private static bool IsChunkedEncryptedFile(string path)
    {
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length < StreamingMagic.Length)
        {
            return false;
        }

        var magic = new byte[StreamingMagic.Length];
        input.ReadExactly(magic);
        return magic.SequenceEqual(StreamingMagic);
    }

    private static byte[] BuildChunkNonce(byte[] prefix, ulong chunkIndex)
    {
        var nonce = new byte[NonceSize];
        prefix.CopyTo(nonce, 0);
        BitConverter.GetBytes(chunkIndex).CopyTo(nonce, prefix.Length);
        return nonce;
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch { }
    }
}

public sealed record EncryptedBlob(string Nonce, string Tag, string Ciphertext);

public static class JsonOptions
{
    public static readonly JsonSerializerOptions Default = new()
    {
        WriteIndented = true
    };
}
