using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.IO;
using System.IO.Compression;

namespace UsbSecureVault;

public sealed class VaultStore
{
    private const string VaultFolderName = "vault";
    private const string ConfigFileName = "config.json";

    public string AppRoot { get; }
    public string VaultRoot { get; }
    public string UsersRoot { get; }
    public string TempRoot { get; }
    public string ConfigPath { get; }

    public VaultConfig? Config { get; private set; }

    public VaultStore()
    {
        AppRoot = Path.GetFullPath(AppContext.BaseDirectory);
        VaultRoot = Path.Combine(AppRoot, VaultFolderName);
        UsersRoot = Path.Combine(VaultRoot, "users");
        TempRoot = Path.Combine(VaultRoot, "temp");
        ConfigPath = Path.Combine(VaultRoot, ConfigFileName);
    }

    public bool IsInitialized => File.Exists(ConfigPath);

    public void EnsureFolders()
    {
        Directory.CreateDirectory(VaultRoot);
        Directory.CreateDirectory(UsersRoot);
        Directory.CreateDirectory(TempRoot);
    }

    public void CleanTemp()
    {
        EnsureFolders();
        foreach (var file in Directory.EnumerateFiles(TempRoot, "*", SearchOption.AllDirectories))
        {
            TryShredFile(file);
        }

        foreach (var dir in Directory.EnumerateDirectories(TempRoot))
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    public VaultConfig LoadConfig()
    {
        Config = JsonSerializer.Deserialize<VaultConfig>(File.ReadAllText(ConfigPath), JsonOptions.Default)
                 ?? throw new InvalidOperationException("Kasa ayarları okunamadı.");
        return Config;
    }

    public void Initialize(string masterPassword, string hint, string emergencyInfo)
    {
        EnsureFolders();
        var salt = CryptoService.RandomBytes(CryptoService.SaltSize);
        var config = new VaultConfig
        {
            VaultId = Guid.NewGuid().ToString("N"),
            MasterSalt = CryptoService.ToBase64(salt),
            MasterHash = CryptoService.PasswordVerifier(masterPassword, salt, 600_000),
            MasterHint = hint.Trim(),
            EmergencyInfo = emergencyInfo.Trim(),
            CreatedAt = DateTimeOffset.UtcNow
        };
        Config = config;
        SaveConfig();
    }

    public void UpdateEmergencyInfo(string emergencyInfo)
    {
        var config = Config ?? LoadConfig();
        config.EmergencyInfo = emergencyInfo.Trim();
        SaveConfig();
    }

    private void SaveConfig()
    {
        if (Config is null)
        {
            throw new InvalidOperationException("Kasa ayarları yüklü değil.");
        }

        File.WriteAllText(ConfigPath, JsonSerializer.Serialize(Config, JsonOptions.Default));
    }

    public bool VerifyMaster(string password)
    {
        var config = Config ?? LoadConfig();
        return CryptoService.VerifyPassword(password, config.MasterSalt, config.KdfIterations, config.MasterHash);
    }

    public string TrustFilePath()
    {
        var config = Config ?? LoadConfig();
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        return Path.Combine(documents, "UsbSecureVaultTrust", $"{config.VaultId}.trust");
    }

    public bool IsTrustedComputer()
    {
        var path = TrustFilePath();
        if (!File.Exists(path))
        {
            return false;
        }

        var expected = (Config ?? LoadConfig()).VaultId;
        return File.ReadAllText(path).Trim() == expected;
    }

    public void TrustThisComputer()
    {
        var path = TrustFilePath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, (Config ?? LoadConfig()).VaultId);
    }

    public List<UserRecord> LoadUsers()
    {
        EnsureFolders();
        return Directory.EnumerateFiles(UsersRoot, "user.json", SearchOption.AllDirectories)
            .Select(path => JsonSerializer.Deserialize<UserRecord>(File.ReadAllText(path), JsonOptions.Default))
            .Where(user => user is not null)
            .Cast<UserRecord>()
            .OrderBy(user => user.Name, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    public UserRecord CreateUser(string name, string password, string hint)
    {
        EnsureFolders();
        var userId = Guid.NewGuid().ToString("N");
        var userRoot = GetUserRoot(userId);
        Directory.CreateDirectory(userRoot);
        Directory.CreateDirectory(GetUserFilesRoot(userId));

        var passwordSalt = CryptoService.RandomBytes(CryptoService.SaltSize);
        var passwordKey = CryptoService.DeriveKey(password, passwordSalt, 600_000);
        var fileKey = CryptoService.RandomBytes(CryptoService.KeySize);
        var wrapped = CryptoService.EncryptBytes(passwordKey, fileKey, CryptoService.Utf8(userId));

        var user = new UserRecord
        {
            Id = userId,
            Name = name.Trim(),
            PasswordSalt = CryptoService.ToBase64(passwordSalt),
            PasswordHash = CryptoService.PasswordVerifier(password, passwordSalt, 600_000),
            PasswordHint = hint.Trim(),
            WrappedKeyNonce = wrapped.Nonce,
            WrappedKeyTag = wrapped.Tag,
            WrappedKeyCiphertext = wrapped.Ciphertext,
            UnlockedKey = fileKey
        };

        SaveUser(user);
        CryptographicOperations.ZeroMemory(passwordKey);
        return user;
    }

    public bool TryUnlockUser(UserRecord user, string password, out string error)
    {
        error = "";
        if (!CryptoService.VerifyPassword(password, user.PasswordSalt, user.KdfIterations, user.PasswordHash))
        {
            error = "Alan şifresi hatalı.";
            return false;
        }

        var passwordKey = CryptoService.DeriveKey(password, CryptoService.FromBase64(user.PasswordSalt), user.KdfIterations);
        try
        {
            user.UnlockedKey = CryptoService.DecryptBytes(
                passwordKey,
                new EncryptedBlob(user.WrappedKeyNonce, user.WrappedKeyTag, user.WrappedKeyCiphertext),
                CryptoService.Utf8(user.Id));
            return true;
        }
        catch (CryptographicException)
        {
            error = "Alan anahtarı açılamadı.";
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordKey);
        }
    }

    public FileRecord AddFile(UserRecord user, string sourcePath)
    {
        if (user.UnlockedKey is null)
        {
            throw new InvalidOperationException("Alan kilitli.");
        }

        var metadata = new FileMetadata
        {
            OriginalName = Path.GetFileName(sourcePath),
            OriginalExtension = Path.GetExtension(sourcePath),
            OriginalRelativeDirectory = GetRelativeDirectory(Path.GetDirectoryName(sourcePath)!),
            OriginalLength = new FileInfo(sourcePath).Length,
            OriginalLastWriteTime = new DateTimeOffset(DateTime.SpecifyKind(File.GetLastWriteTimeUtc(sourcePath), DateTimeKind.Utc)),
            IsFolder = false
        };

        var id = Guid.NewGuid().ToString("N");
        var storedName = $"{Guid.NewGuid():N}.usv";
        var destination = Path.Combine(GetUserFilesRoot(user.Id), storedName);
        CryptoService.EncryptFileInPlaceAndMove(user.UnlockedKey, sourcePath, destination, out var contentNonce, out var contentTag);

        var metadataBlob = CryptoService.EncryptJson(user.UnlockedKey, metadata, CryptoService.Utf8(id));
        var record = new FileRecord
        {
            Id = id,
            StoredName = storedName,
            ContentNonce = contentNonce,
            ContentTag = contentTag,
            CipherLength = new FileInfo(destination).Length,
            MetadataNonce = metadataBlob.Nonce,
            MetadataTag = metadataBlob.Tag,
            MetadataCiphertext = metadataBlob.Ciphertext,
            AddedAt = DateTimeOffset.UtcNow
        };

        user.Files.Add(record);
        SaveUser(user);
        return record;
    }

    public FileRecord AddFolder(UserRecord user, string sourcePath)
    {
        if (user.UnlockedKey is null)
        {
            throw new InvalidOperationException("Alan kilitli.");
        }

        var packagePath = Path.Combine(TempRoot, $"{Guid.NewGuid():N}.zip");
        ZipFile.CreateFromDirectory(sourcePath, packagePath, CompressionLevel.NoCompression, false);

        try
        {
            var metadata = new FileMetadata
            {
                OriginalName = new DirectoryInfo(sourcePath).Name,
                OriginalExtension = ".zip",
                OriginalRelativeDirectory = GetRelativeDirectory(Directory.GetParent(sourcePath)?.FullName ?? AppRoot),
                OriginalLength = GetDirectorySize(sourcePath),
                OriginalLastWriteTime = new DateTimeOffset(DateTime.SpecifyKind(Directory.GetLastWriteTimeUtc(sourcePath), DateTimeKind.Utc)),
                IsFolder = true
            };

            var id = Guid.NewGuid().ToString("N");
            var storedName = $"{Guid.NewGuid():N}.usv";
            var destination = Path.Combine(GetUserFilesRoot(user.Id), storedName);
            CryptoService.EncryptFileFromPathToPath(user.UnlockedKey, packagePath, destination, out var contentNonce, out var contentTag);

            var metadataBlob = CryptoService.EncryptJson(user.UnlockedKey, metadata, CryptoService.Utf8(id));
            var record = new FileRecord
            {
                Id = id,
                StoredName = storedName,
                ContentNonce = contentNonce,
                ContentTag = contentTag,
                CipherLength = new FileInfo(destination).Length,
                MetadataNonce = metadataBlob.Nonce,
                MetadataTag = metadataBlob.Tag,
                MetadataCiphertext = metadataBlob.Ciphertext,
                AddedAt = DateTimeOffset.UtcNow
            };

            user.Files.Add(record);
            SaveUser(user);
            Directory.Delete(sourcePath, true);
            return record;
        }
        finally
        {
            TryDelete(packagePath);
        }
    }

    public FileMetadata ReadMetadata(UserRecord user, FileRecord record)
    {
        if (user.UnlockedKey is null)
        {
            throw new InvalidOperationException("Alan kilitli.");
        }

        return CryptoService.DecryptJson<FileMetadata>(
            user.UnlockedKey,
            new EncryptedBlob(record.MetadataNonce, record.MetadataTag, record.MetadataCiphertext),
            CryptoService.Utf8(record.Id));
    }

    public string DecryptToTemp(UserRecord user, FileRecord record)
    {
        if (user.UnlockedKey is null)
        {
            throw new InvalidOperationException("Alan kilitli.");
        }

        var metadata = ReadMetadata(user, record);
        var tempDir = Path.Combine(TempRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var tempPath = Path.Combine(tempDir, metadata.OriginalName);
        var encryptedPath = Path.Combine(GetUserFilesRoot(user.Id), record.StoredName);
        CryptoService.DecryptFileToPath(user.UnlockedKey, record, encryptedPath, tempPath);
        return tempPath;
    }

    public string DecryptFolderToTemp(UserRecord user, FileRecord record)
    {
        if (user.UnlockedKey is null)
        {
            throw new InvalidOperationException("Alan kilitli.");
        }

        var metadata = ReadMetadata(user, record);
        var tempDir = Path.Combine(TempRoot, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        var zipPath = Path.Combine(tempDir, $"{Guid.NewGuid():N}.zip");
        var encryptedPath = Path.Combine(GetUserFilesRoot(user.Id), record.StoredName);
        CryptoService.DecryptFileToPath(user.UnlockedKey, record, encryptedPath, zipPath);

        var folderPath = Path.Combine(tempDir, metadata.OriginalName);
        Directory.CreateDirectory(folderPath);
        ZipFile.ExtractToDirectory(zipPath, folderPath, true);
        TryDelete(zipPath);
        return folderPath;
    }

    public void DeleteFile(UserRecord user, FileRecord record)
    {
        var encryptedPath = Path.Combine(GetUserFilesRoot(user.Id), record.StoredName);
        if (File.Exists(encryptedPath))
        {
            ShredFile(encryptedPath);
        }

        user.Files.RemoveAll(file => file.Id == record.Id);
        SaveUser(user);
    }

    public void DeleteUser(UserRecord user, bool restoreContents)
    {
        if (restoreContents && user.UnlockedKey is null)
        {
            throw new InvalidOperationException("Alan kilitli.");
        }

        foreach (var record in user.Files.ToList())
        {
            if (restoreContents)
            {
                RestoreToOriginalLocation(user, record);
            }
            else
            {
                var encryptedPath = Path.Combine(GetUserFilesRoot(user.Id), record.StoredName);
                if (File.Exists(encryptedPath))
                {
                    ShredFile(encryptedPath);
                }

                user.Files.RemoveAll(file => file.Id == record.Id);
            }
        }

        var userRoot = GetUserRoot(user.Id);
        if (Directory.Exists(userRoot))
        {
            ShredDirectory(userRoot);
        }
    }

    public void DeleteVault(IEnumerable<UserRecord> users, bool restoreContents)
    {
        if (restoreContents)
        {
            foreach (var user in users.ToList())
            {
                DeleteUser(user, true);
            }
        }

        if (Directory.Exists(VaultRoot))
        {
            ShredDirectory(VaultRoot);
        }

        Config = null;
    }

    public string RestoreToOriginalLocation(UserRecord user, FileRecord record)
    {
        if (user.UnlockedKey is null)
        {
            throw new InvalidOperationException("Alan kilitli.");
        }

        var metadata = ReadMetadata(user, record);
        var targetDirectory = GetOriginalDirectory(metadata);
        Directory.CreateDirectory(targetDirectory);

        if (metadata.IsFolder)
        {
            var targetFolder = Path.Combine(targetDirectory, metadata.OriginalName);
            if (Directory.Exists(targetFolder) || File.Exists(targetFolder))
            {
                throw new IOException("Eski konumda aynı isimde bir dosya veya klasör var.");
            }

            var tempFolder = DecryptFolderToTemp(user, record);
            try
            {
                Directory.Move(tempFolder, targetFolder);
                DeleteFile(user, record);
                TryDeleteTempParent(tempFolder);
                return targetFolder;
            }
            catch
            {
                if (Directory.Exists(targetFolder))
                {
                    try { Directory.Move(targetFolder, tempFolder); } catch { }
                }

                throw;
            }
        }

        var targetPath = Path.Combine(targetDirectory, metadata.OriginalName);
        if (File.Exists(targetPath) || Directory.Exists(targetPath))
        {
            throw new IOException("Eski konumda aynı isimde bir dosya veya klasör var.");
        }

        var encryptedPath = Path.Combine(GetUserFilesRoot(user.Id), record.StoredName);
        CryptoService.DecryptFileToPath(user.UnlockedKey, record, encryptedPath, targetPath);
        File.SetLastWriteTimeUtc(targetPath, metadata.OriginalLastWriteTime.UtcDateTime);
        DeleteFile(user, record);
        return targetPath;
    }

    public void OpenTempAndSaveAfterExit(UserRecord user, FileRecord record, string path, Action? afterSave = null)
    {
        if (user.UnlockedKey is null)
        {
            return;
        }

        var sessionKey = user.UnlockedKey.ToArray();
        var process = Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        if (process is null)
        {
            CryptographicOperations.ZeroMemory(sessionKey);
            return;
        }

        Task.Run(() =>
        {
            try
            {
                try { process.WaitForExit(); } catch { }
                TrySaveFileBack(user, record, path, sessionKey);
                TryDelete(path);
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrWhiteSpace(dir))
                {
                    try { Directory.Delete(dir, true); } catch { }
                }
                afterSave?.Invoke();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sessionKey);
            }
        });
    }

    public void SaveFolderBackAndClean(UserRecord user, FileRecord record, string folderPath)
    {
        if (user.UnlockedKey is null)
        {
            return;
        }

        var sessionKey = user.UnlockedKey.ToArray();
        var zipPath = Path.Combine(Path.GetDirectoryName(folderPath)!, $"{Guid.NewGuid():N}.zip");
        try
        {
            if (File.Exists(zipPath))
            {
                File.Delete(zipPath);
            }

            ZipFile.CreateFromDirectory(folderPath, zipPath, CompressionLevel.NoCompression, false);
            TrySavePackageBack(user, record, zipPath, sessionKey, new FileMetadata
            {
                OriginalName = new DirectoryInfo(folderPath).Name,
                OriginalExtension = ".zip",
                OriginalLength = GetDirectorySize(folderPath),
                OriginalLastWriteTime = new DateTimeOffset(DateTime.SpecifyKind(Directory.GetLastWriteTimeUtc(folderPath), DateTimeKind.Utc)),
                IsFolder = true
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sessionKey);
            TryDelete(zipPath);
            try { Directory.Delete(Path.GetDirectoryName(folderPath)!, true); } catch { }
        }
    }

    private void TrySaveFileBack(UserRecord user, FileRecord record, string path, byte[] key)
    {
        if (!File.Exists(path))
        {
            return;
        }

        TrySavePackageBack(user, record, path, key, new FileMetadata
        {
            OriginalName = Path.GetFileName(path),
            OriginalExtension = Path.GetExtension(path),
            OriginalLength = new FileInfo(path).Length,
            OriginalLastWriteTime = new DateTimeOffset(DateTime.SpecifyKind(File.GetLastWriteTimeUtc(path), DateTimeKind.Utc)),
            IsFolder = false
        });
    }

    private void TrySavePackageBack(UserRecord user, FileRecord record, string packagePath, byte[] key, FileMetadata metadata)
    {
        var encryptedPath = Path.Combine(GetUserFilesRoot(user.Id), record.StoredName);
        var attempts = 0;
        while (true)
        {
            try
            {
                CryptoService.EncryptFileFromPathToPath(key, packagePath, encryptedPath, out var nonce, out var tag);
                record.ContentNonce = nonce;
                record.ContentTag = tag;
                record.CipherLength = new FileInfo(encryptedPath).Length;
                var metadataBlob = CryptoService.EncryptJson(key, metadata, CryptoService.Utf8(record.Id));
                record.MetadataNonce = metadataBlob.Nonce;
                record.MetadataTag = metadataBlob.Tag;
                record.MetadataCiphertext = metadataBlob.Ciphertext;
                SaveUser(user);
                return;
            }
            catch (IOException) when (++attempts < 10)
            {
                Thread.Sleep(500);
            }
            catch (UnauthorizedAccessException) when (++attempts < 10)
            {
                Thread.Sleep(500);
            }
        }
    }

    public void SaveUser(UserRecord user)
    {
        var path = GetUserPath(user.Id);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(user, JsonOptions.Default));
    }

    private string GetUserRoot(string userId) => Path.Combine(UsersRoot, userId);

    private string GetUserFilesRoot(string userId)
    {
        var path = Path.Combine(GetUserRoot(userId), "files");
        Directory.CreateDirectory(path);
        return path;
    }

    private string GetUserPath(string userId) => Path.Combine(GetUserRoot(userId), "user.json");

    private string GetRelativeDirectory(string path)
    {
        var relative = Path.GetRelativePath(AppRoot, Path.GetFullPath(path));
        return relative == "." ? "" : relative;
    }

    private string GetOriginalDirectory(FileMetadata metadata)
    {
        if (string.IsNullOrWhiteSpace(metadata.OriginalRelativeDirectory))
        {
            return AppRoot;
        }

        var combined = Path.GetFullPath(Path.Combine(AppRoot, metadata.OriginalRelativeDirectory));
        var appRoot = Path.GetFullPath(AppRoot);
        if (!combined.StartsWith(appRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Kayıtlı eski konum USB kökünün dışında.");
        }

        return combined;
    }

    private static void TryDeleteTempParent(string path)
    {
        var parent = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(parent))
        {
            try { Directory.Delete(parent, true); } catch { }
        }
    }

    private static long GetDirectorySize(string path)
    {
        return Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories)
            .Sum(file => new FileInfo(file).Length);
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);
            }
        }
        catch { }
    }

    private static void ShredDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            ShredFile(file);
        }

        foreach (var dir in Directory.EnumerateDirectories(path, "*", SearchOption.AllDirectories)
                     .OrderByDescending(dir => dir.Length))
        {
            try { Directory.Delete(dir, false); } catch { }
        }

        try { Directory.Delete(path, false); } catch { }
    }

    private static void ShredFile(string path)
    {
        File.SetAttributes(path, FileAttributes.Normal);
        var buffer = new byte[1024 * 1024];
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None, buffer.Length))
        {
            var remaining = stream.Length;
            stream.Position = 0;
            while (remaining > 0)
            {
                var write = (int)Math.Min(buffer.Length, remaining);
                RandomNumberGenerator.Fill(buffer.AsSpan(0, write));
                stream.Write(buffer, 0, write);
                remaining -= write;
            }

            stream.Flush(true);
        }

        CryptographicOperations.ZeroMemory(buffer);
        File.Delete(path);
    }

    private static void TryShredFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                ShredFile(path);
            }
        }
        catch
        {
            TryDelete(path);
        }
    }
}
