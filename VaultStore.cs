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
    private const string FolderManifestFileName = "folder.usvm";
    private const string StoredItemExtension = ".dat";
    private const string PendingItemExtension = ".pending";
    private const int ObfuscationMaskSize = 64 * 1024;

    public string AppRoot { get; }
    public string VaultRoot { get; }
    public string UsersRoot { get; }
    public string TempRoot { get; }
    public string LogsRoot { get; }
    public string ConfigPath { get; }

    public VaultConfig? Config { get; private set; }

    public VaultStore()
    {
        AppRoot = Path.GetFullPath(AppContext.BaseDirectory);
        VaultRoot = Path.Combine(AppRoot, VaultFolderName);
        UsersRoot = Path.Combine(VaultRoot, "users");
        TempRoot = Path.Combine(VaultRoot, "temp");
        LogsRoot = Path.Combine(VaultRoot, "logs");
        ConfigPath = Path.Combine(VaultRoot, ConfigFileName);
    }

    public bool IsInitialized => File.Exists(ConfigPath);

    public void EnsureFolders()
    {
        Directory.CreateDirectory(VaultRoot);
        Directory.CreateDirectory(UsersRoot);
        Directory.CreateDirectory(TempRoot);
        Directory.CreateDirectory(LogsRoot);
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

        foreach (var dir in Directory.EnumerateDirectories(UsersRoot, $"*{PendingItemExtension}", SearchOption.AllDirectories))
        {
            try { ShredDirectory(dir); } catch { }
        }
    }

    public VaultConfig LoadConfig()
    {
        Config = JsonSerializer.Deserialize<VaultConfig>(File.ReadAllText(ConfigPath), JsonOptions.Default)
                 ?? throw new InvalidOperationException("Kasa ayarları okunamadı.");
        return Config;
    }

    public void Initialize(bool useMasterPassword, string masterPassword, string hint, string emergencyInfo)
    {
        EnsureFolders();
        var salt = useMasterPassword ? CryptoService.RandomBytes(CryptoService.SaltSize) : [];
        var config = new VaultConfig
        {
            VaultId = Guid.NewGuid().ToString("N"),
            MasterPasswordEnabled = useMasterPassword,
            MasterSalt = useMasterPassword ? CryptoService.ToBase64(salt) : "",
            MasterHash = useMasterPassword ? CryptoService.PasswordVerifier(masterPassword, salt, 600_000) : "",
            MasterHint = useMasterPassword ? hint.Trim() : "",
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

        AtomicWriteAllText(ConfigPath, JsonSerializer.Serialize(Config, JsonOptions.Default));
    }

    public bool VerifyMaster(string password)
    {
        var config = Config ?? LoadConfig();
        if (!config.MasterPasswordEnabled)
        {
            return true;
        }

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

    public UserRecord CreateUser(string name, bool usePassword, string password, string hint)
    {
        EnsureFolders();
        var userId = Guid.NewGuid().ToString("N");
        var userRoot = GetUserRoot(userId);
        Directory.CreateDirectory(userRoot);
        Directory.CreateDirectory(GetUserFilesRoot(userId));

        var effectivePassword = usePassword ? password : "";
        var passwordSalt = CryptoService.RandomBytes(CryptoService.SaltSize);
        var passwordKey = CryptoService.DeriveKey(effectivePassword, passwordSalt, 600_000);
        var fileKey = CryptoService.RandomBytes(CryptoService.KeySize);
        var wrapped = CryptoService.EncryptBytes(passwordKey, fileKey, CryptoService.Utf8(userId));

        var user = new UserRecord
        {
            Id = userId,
            Name = name.Trim(),
            PasswordEnabled = usePassword,
            PasswordSalt = CryptoService.ToBase64(passwordSalt),
            PasswordHash = CryptoService.PasswordVerifier(effectivePassword, passwordSalt, 600_000),
            PasswordHint = usePassword ? hint.Trim() : "",
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
        var effectivePassword = user.PasswordEnabled ? password : "";
        if (!CryptoService.VerifyPassword(effectivePassword, user.PasswordSalt, user.KdfIterations, user.PasswordHash))
        {
            error = "Alan şifresi hatalı.";
            return false;
        }

        var passwordKey = CryptoService.DeriveKey(effectivePassword, CryptoService.FromBase64(user.PasswordSalt), user.KdfIterations);
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

    public FileRecord AddFile(UserRecord user, string sourcePath, FileAddMode mode, IProgress<FileOperationProgress>? progress = null)
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

        var totalBytes = Math.Max(1, metadata.OriginalLength * 2);
        long completedBytes = 0;
        void ReportDelta(long bytes, string message)
        {
            completedBytes = Math.Min(totalBytes, completedBytes + Math.Max(0, bytes));
            progress?.Report(new FileOperationProgress
            {
                Message = message,
                CompletedBytes = completedBytes,
                TotalBytes = totalBytes
            });
        }

        progress?.Report(new FileOperationProgress { Message = "Dosya hazırlanıyor...", CompletedBytes = 0, TotalBytes = totalBytes });

        var id = Guid.NewGuid().ToString("N");
        var storageMode = mode == FileAddMode.Obfuscate ? FileStorageModes.Obfuscated : FileStorageModes.Encrypted;
        var storedName = NewStoredItemName();
        var destination = Path.Combine(GetUserFilesRoot(user.Id), storedName);
        var contentNonce = "";
        var contentTag = "";
        var obfuscationNonce = "";
        long obfuscationPrefixLength = 0;
        long obfuscationSuffixLength = 0;
        if (storageMode == FileStorageModes.Obfuscated)
        {
            CopyFileWithProgress(sourcePath, destination, false, new Progress<long>(bytes => ReportDelta(bytes, "Dosya kasaya kopyalanıyor...")));
            (obfuscationNonce, obfuscationPrefixLength, obfuscationSuffixLength) = MaskObfuscatedFile(destination);
        }
        else
        {
            CryptoService.EncryptFileToPath(user.UnlockedKey, sourcePath, destination, out contentNonce, out contentTag, new Progress<long>(bytes => ReportDelta(bytes, "Dosya şifreleniyor...")));
        }

        var metadataBlob = CryptoService.EncryptJson(user.UnlockedKey, metadata, CryptoService.Utf8(id));
        var record = new FileRecord
        {
            Id = id,
            StoredName = storedName,
            StorageMode = storageMode,
            ContentNonce = contentNonce,
            ContentTag = contentTag,
            ObfuscationNonce = obfuscationNonce,
            ObfuscationPrefixLength = obfuscationPrefixLength,
            ObfuscationSuffixLength = obfuscationSuffixLength,
            CipherLength = new FileInfo(destination).Length,
            MetadataNonce = metadataBlob.Nonce,
            MetadataTag = metadataBlob.Tag,
            MetadataCiphertext = metadataBlob.Ciphertext,
            AddedAt = DateTimeOffset.UtcNow
        };

        user.Files.Add(record);
        SaveUser(user);
        TryShredFile(sourcePath, new Progress<long>(bytes => ReportDelta(bytes, "Orijinal dosya güvenli siliniyor...")));
        progress?.Report(new FileOperationProgress { Message = "Tamamlandı.", CompletedBytes = totalBytes, TotalBytes = totalBytes });
        return record;
    }

    public FileRecord AddFolder(UserRecord user, string sourcePath, FileAddMode mode, IProgress<FileOperationProgress>? progress = null)
    {
        var plan = BuildUniformFolderPlan(sourcePath, mode);
        return AddFolder(user, sourcePath, plan, progress);
    }

    public FileRecord AddFolder(UserRecord user, string sourcePath, FolderImportPlan plan, IProgress<FileOperationProgress>? progress = null)
    {
        if (user.UnlockedKey is null)
        {
            throw new InvalidOperationException("Alan kilitli.");
        }

        var metadata = new FileMetadata
        {
            OriginalName = new DirectoryInfo(sourcePath).Name,
            OriginalExtension = "",
            OriginalRelativeDirectory = GetRelativeDirectory(Directory.GetParent(sourcePath)?.FullName ?? AppRoot),
            OriginalLength = GetDirectorySize(sourcePath),
            OriginalLastWriteTime = new DateTimeOffset(DateTime.SpecifyKind(Directory.GetLastWriteTimeUtc(sourcePath), DateTimeKind.Utc)),
            IsFolder = true
        };

        var totalBytes = Math.Max(1, metadata.OriginalLength * 2);
        long completedBytes = 0;
        void ReportDelta(long bytes, string message)
        {
            completedBytes = Math.Min(totalBytes, completedBytes + Math.Max(0, bytes));
            progress?.Report(new FileOperationProgress
            {
                Message = message,
                CompletedBytes = completedBytes,
                TotalBytes = totalBytes
            });
        }

        progress?.Report(new FileOperationProgress { Message = "Klasör hazırlanıyor...", CompletedBytes = 0, TotalBytes = totalBytes });

        var id = Guid.NewGuid().ToString("N");
        var storedName = NewStoredItemName();
        var filesRoot = GetUserFilesRoot(user.Id);
        var staging = Path.Combine(filesRoot, $"{Guid.NewGuid():N}{PendingItemExtension}");
        var destination = Path.Combine(filesRoot, storedName);
        Directory.CreateDirectory(staging);
        try
        {
            var manifestName = WriteFolderTreeToVault(user.UnlockedKey, plan, staging, new Progress<long>(bytes => ReportDelta(bytes, "Klasör kasaya yazılıyor...")));
            Directory.Move(staging, destination);

            var metadataBlob = CryptoService.EncryptJson(user.UnlockedKey, metadata, CryptoService.Utf8(id));
            var record = new FileRecord
            {
                Id = id,
                StoredName = storedName,
                FolderManifestName = manifestName,
                StorageMode = FileStorageModes.FolderTree,
                ContentNonce = "",
                ContentTag = "",
                CipherLength = GetDirectorySize(destination),
                MetadataNonce = metadataBlob.Nonce,
                MetadataTag = metadataBlob.Tag,
                MetadataCiphertext = metadataBlob.Ciphertext,
                AddedAt = DateTimeOffset.UtcNow
            };

            user.Files.Add(record);
            SaveUser(user);
            TryShredDirectory(sourcePath, new Progress<long>(bytes => ReportDelta(bytes, "Orijinal klasör güvenli siliniyor...")));
            progress?.Report(new FileOperationProgress { Message = "Tamamlandı.", CompletedBytes = totalBytes, TotalBytes = totalBytes });
            return record;
        }
        catch
        {
            try { ShredDirectory(staging); } catch { }
            try { ShredDirectory(destination); } catch { }
            throw;
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
        if (IsObfuscated(record))
        {
            File.Copy(encryptedPath, tempPath, false);
            ApplyObfuscationMask(tempPath, record.ObfuscationNonce, record.ObfuscationPrefixLength, record.ObfuscationSuffixLength);
        }
        else
        {
            CryptoService.DecryptFileToPath(user.UnlockedKey, record, encryptedPath, tempPath);
        }
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
        var folderPath = Path.Combine(tempDir, metadata.OriginalName);
        if (IsFolderTree(record))
        {
            Directory.CreateDirectory(folderPath);
            ExtractFolderTreeFromVault(user.UnlockedKey, encryptedPath, folderPath, record.FolderManifestName);
        }
        else if (IsObfuscated(record))
        {
            CopyDirectory(encryptedPath, folderPath);
        }
        else
        {
            CryptoService.DecryptFileToPath(user.UnlockedKey, record, encryptedPath, zipPath);
            Directory.CreateDirectory(folderPath);
            ZipFile.ExtractToDirectory(zipPath, folderPath, true);
            TryDelete(zipPath);
        }
        return folderPath;
    }

    public bool CanBrowseFolder(UserRecord user, FileRecord record)
    {
        return user.UnlockedKey is not null && IsFolderTree(record);
    }

    public List<VaultFolderItem> ListFolderItems(UserRecord user, FileRecord record, string relativeFolder)
    {
        if (user.UnlockedKey is null)
        {
            throw new InvalidOperationException("Alan kilitli.");
        }

        if (!IsFolderTree(record))
        {
            throw new InvalidOperationException("Bu klasör lazy gezintiyi desteklemiyor.");
        }

        var storedRoot = Path.Combine(GetUserFilesRoot(user.Id), record.StoredName);
        var location = ResolveFolderLocation(user.UnlockedKey, storedRoot, record.FolderManifestName, SplitRelativePath(relativeFolder));
        var manifest = ReadFolderManifest(user.UnlockedKey, location.StoredPath, location.ManifestName);
        return manifest.Entries
            .OrderByDescending(entry => entry.IsFolder)
            .ThenBy(entry => entry.OriginalName, StringComparer.CurrentCultureIgnoreCase)
            .Select(entry => new VaultFolderItem
            {
                Name = entry.OriginalName,
                RelativePath = CombineRelativePath(relativeFolder, entry.OriginalName),
                IsFolder = entry.IsFolder,
                Length = entry.OriginalLength,
                LastWriteTime = entry.OriginalLastWriteTime,
                StorageMode = entry.StorageMode
            })
            .ToList();
    }

    public void OpenFolderTreeFileAndSaveAfterExit(UserRecord user, FileRecord record, string relativeFilePath, Action? afterSave = null)
    {
        if (user.UnlockedKey is null)
        {
            return;
        }

        if (!IsFolderTree(record))
        {
            throw new InvalidOperationException("Bu klasör lazy gezintiyi desteklemiyor.");
        }

        var sessionKey = user.UnlockedKey.ToArray();
        var metadata = ReadMetadata(user, record);
        var tempRoot = Path.Combine(TempRoot, Guid.NewGuid().ToString("N"), metadata.OriginalName);
        var tempPath = ExtractFolderTreeFileToTemp(sessionKey, user, record, relativeFilePath, tempRoot);
        var process = Process.Start(new ProcessStartInfo(tempPath) { UseShellExecute = true });
        if (process is null)
        {
            CryptographicOperations.ZeroMemory(sessionKey);
            TryDeleteTempParent(tempRoot);
            return;
        }

        Task.Run(() =>
        {
            try
            {
                try { process.WaitForExit(); } catch { }
                SaveFolderTreeTempFileBack(user, record, relativeFilePath, tempPath, sessionKey);
                TryDeleteTempParent(tempRoot);
                afterSave?.Invoke();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sessionKey);
            }
        });
    }

    public void DeleteFile(UserRecord user, FileRecord record)
    {
        var encryptedPath = Path.Combine(GetUserFilesRoot(user.Id), record.StoredName);
        if (File.Exists(encryptedPath))
        {
            ShredFile(encryptedPath);
        }
        else if (Directory.Exists(encryptedPath))
        {
            ShredDirectory(encryptedPath);
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
                else if (Directory.Exists(encryptedPath))
                {
                    ShredDirectory(encryptedPath);
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

            if (IsObfuscated(record))
            {
                var storedFolder = Path.Combine(GetUserFilesRoot(user.Id), record.StoredName);
                Directory.Move(storedFolder, targetFolder);
                user.Files.RemoveAll(file => file.Id == record.Id);
                SaveUser(user);
                return targetFolder;
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
        if (IsObfuscated(record))
        {
            File.Move(encryptedPath, targetPath);
            ApplyObfuscationMask(targetPath, record.ObfuscationNonce, record.ObfuscationPrefixLength, record.ObfuscationSuffixLength);
            File.SetLastWriteTimeUtc(targetPath, metadata.OriginalLastWriteTime.UtcDateTime);
            user.Files.RemoveAll(file => file.Id == record.Id);
            SaveUser(user);
            return targetPath;
        }

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
        try
        {
            var existingMetadata = ReadMetadata(user, record);
            if (IsFolderTree(record))
            {
                TrySaveFolderTreeBack(user, record, folderPath, sessionKey, new FileMetadata
                {
                    OriginalName = new DirectoryInfo(folderPath).Name,
                    OriginalExtension = "",
                    OriginalRelativeDirectory = existingMetadata.OriginalRelativeDirectory,
                    OriginalLength = GetDirectorySize(folderPath),
                    OriginalLastWriteTime = new DateTimeOffset(DateTime.SpecifyKind(Directory.GetLastWriteTimeUtc(folderPath), DateTimeKind.Utc)),
                    IsFolder = true
                });
                return;
            }

            if (IsObfuscated(record))
            {
                TrySaveObfuscatedFolderBack(user, record, folderPath, sessionKey, new FileMetadata
                {
                    OriginalName = new DirectoryInfo(folderPath).Name,
                    OriginalExtension = "",
                    OriginalRelativeDirectory = existingMetadata.OriginalRelativeDirectory,
                    OriginalLength = GetDirectorySize(folderPath),
                    OriginalLastWriteTime = new DateTimeOffset(DateTime.SpecifyKind(Directory.GetLastWriteTimeUtc(folderPath), DateTimeKind.Utc)),
                    IsFolder = true
                });
                return;
            }

            var zipPath = Path.Combine(Path.GetDirectoryName(folderPath)!, $"{Guid.NewGuid():N}.zip");
            if (File.Exists(zipPath))
            {
                File.Delete(zipPath);
            }

            try
            {
                ZipFile.CreateFromDirectory(folderPath, zipPath, CompressionLevel.NoCompression, false);
                TrySavePackageBack(user, record, zipPath, sessionKey, new FileMetadata
                {
                    OriginalName = new DirectoryInfo(folderPath).Name,
                    OriginalExtension = ".zip",
                    OriginalRelativeDirectory = existingMetadata.OriginalRelativeDirectory,
                    OriginalLength = GetDirectorySize(folderPath),
                    OriginalLastWriteTime = new DateTimeOffset(DateTime.SpecifyKind(Directory.GetLastWriteTimeUtc(folderPath), DateTimeKind.Utc)),
                    IsFolder = true
                });
            }
            finally
            {
                TryDelete(zipPath);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sessionKey);
            try { Directory.Delete(Path.GetDirectoryName(folderPath)!, true); } catch { }
        }
    }

    private void TrySaveFileBack(UserRecord user, FileRecord record, string path, byte[] key)
    {
        if (!File.Exists(path))
        {
            return;
        }

        var existingMetadata = ReadMetadata(user, record);
        if (IsObfuscated(record))
        {
            TrySaveObfuscatedFileBack(user, record, path, key, new FileMetadata
            {
                OriginalName = Path.GetFileName(path),
                OriginalExtension = Path.GetExtension(path),
                OriginalRelativeDirectory = existingMetadata.OriginalRelativeDirectory,
                OriginalLength = new FileInfo(path).Length,
                OriginalLastWriteTime = new DateTimeOffset(DateTime.SpecifyKind(File.GetLastWriteTimeUtc(path), DateTimeKind.Utc)),
                IsFolder = false
            });
            return;
        }

        TrySavePackageBack(user, record, path, key, new FileMetadata
        {
            OriginalName = Path.GetFileName(path),
            OriginalExtension = Path.GetExtension(path),
            OriginalRelativeDirectory = existingMetadata.OriginalRelativeDirectory,
            OriginalLength = new FileInfo(path).Length,
            OriginalLastWriteTime = new DateTimeOffset(DateTime.SpecifyKind(File.GetLastWriteTimeUtc(path), DateTimeKind.Utc)),
            IsFolder = false
        });
    }

    private void TrySavePackageBack(UserRecord user, FileRecord record, string packagePath, byte[] key, FileMetadata metadata)
    {
        if (IsObfuscated(record))
        {
            TrySaveObfuscatedFolderBack(user, record, packagePath, key, metadata);
            return;
        }

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

    private void TrySaveObfuscatedFileBack(UserRecord user, FileRecord record, string path, byte[] key, FileMetadata metadata)
    {
        var storedPath = Path.Combine(GetUserFilesRoot(user.Id), record.StoredName);
        var attempts = 0;
        while (true)
        {
            try
            {
                File.Copy(path, storedPath, true);
                var (nonce, prefixLength, suffixLength) = MaskObfuscatedFile(storedPath);
                record.ObfuscationNonce = nonce;
                record.ObfuscationPrefixLength = prefixLength;
                record.ObfuscationSuffixLength = suffixLength;
                record.CipherLength = new FileInfo(storedPath).Length;
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

    private void TrySaveObfuscatedFolderBack(UserRecord user, FileRecord record, string folderPath, byte[] key, FileMetadata metadata)
    {
        var storedPath = Path.Combine(GetUserFilesRoot(user.Id), record.StoredName);
        var replacementPath = Path.Combine(GetUserFilesRoot(user.Id), NewStoredItemName());
        CopyDirectory(folderPath, replacementPath);
        if (Directory.Exists(storedPath))
        {
            ShredDirectory(storedPath);
        }

        Directory.Move(replacementPath, storedPath);
        record.CipherLength = GetDirectorySize(storedPath);
        var metadataBlob = CryptoService.EncryptJson(key, metadata, CryptoService.Utf8(record.Id));
        record.MetadataNonce = metadataBlob.Nonce;
        record.MetadataTag = metadataBlob.Tag;
        record.MetadataCiphertext = metadataBlob.Ciphertext;
        SaveUser(user);
    }

    private void TrySaveFolderTreeBack(UserRecord user, FileRecord record, string folderPath, byte[] key, FileMetadata metadata)
    {
        var storedPath = Path.Combine(GetUserFilesRoot(user.Id), record.StoredName);
        var replacementPath = Path.Combine(GetUserFilesRoot(user.Id), NewStoredItemName());
        var modeMap = new Dictionary<string, FileAddMode>(StringComparer.OrdinalIgnoreCase);
        if (Directory.Exists(storedPath))
        {
            CollectFolderTreeModes(key, storedPath, record.FolderManifestName, "", modeMap);
        }

        var plan = BuildUniformFolderPlan(folderPath, FileAddMode.Encrypt);
        ApplyKnownModes(plan, "", modeMap);
        Directory.CreateDirectory(replacementPath);
        try
        {
            var manifestName = WriteFolderTreeToVault(key, plan, replacementPath);
            if (Directory.Exists(storedPath))
            {
                ShredDirectory(storedPath);
            }

            Directory.Move(replacementPath, storedPath);
            record.FolderManifestName = manifestName;
            record.CipherLength = GetDirectorySize(storedPath);
            var metadataBlob = CryptoService.EncryptJson(key, metadata, CryptoService.Utf8(record.Id));
            record.MetadataNonce = metadataBlob.Nonce;
            record.MetadataTag = metadataBlob.Tag;
            record.MetadataCiphertext = metadataBlob.Ciphertext;
            SaveUser(user);
        }
        catch
        {
            try { ShredDirectory(replacementPath); } catch { }
            throw;
        }
    }

    private static string WriteFolderTreeToVault(byte[] key, FolderImportPlan plan, string destinationPath, IProgress<long>? progress = null)
    {
        Directory.CreateDirectory(destinationPath);
        var manifest = new StoredFolderManifest();

        foreach (var child in plan.Children.OrderBy(item => item.Name, StringComparer.CurrentCultureIgnoreCase))
        {
            if (child.IsFolder)
            {
                var sourceDirectory = new DirectoryInfo(child.SourcePath);
                var entry = new StoredFolderEntry
                {
                    OriginalName = sourceDirectory.Name,
                    OriginalExtension = "",
                    OriginalLength = GetDirectorySize(child.SourcePath),
                    OriginalLastWriteTime = new DateTimeOffset(DateTime.SpecifyKind(Directory.GetLastWriteTimeUtc(child.SourcePath), DateTimeKind.Utc)),
                    IsFolder = true,
                    StoredName = NewStoredItemName(),
                    FolderManifestName = "",
                    StorageMode = FileStorageModes.FolderTree
                };

                entry.FolderManifestName = WriteFolderTreeToVault(key, child, Path.Combine(destinationPath, entry.StoredName), progress);
                manifest.Entries.Add(entry);
                continue;
            }

            var fileInfo = new FileInfo(child.SourcePath);
            var originalName = fileInfo.Name;
            var originalExtension = fileInfo.Extension;
            var originalLength = fileInfo.Length;
            var originalLastWriteTime = new DateTimeOffset(DateTime.SpecifyKind(fileInfo.LastWriteTimeUtc, DateTimeKind.Utc));
            var mode = child.Mode == FileAddMode.Obfuscate ? FileStorageModes.Obfuscated : FileStorageModes.Encrypted;
            var storedName = NewStoredItemName();
            var storedPath = Path.Combine(destinationPath, storedName);
            var contentNonce = "";
            var contentTag = "";
            var obfuscationNonce = "";
            long obfuscationPrefixLength = 0;
            long obfuscationSuffixLength = 0;
            if (mode == FileStorageModes.Obfuscated)
            {
                CopyFileWithProgress(child.SourcePath, storedPath, false, progress);
                (obfuscationNonce, obfuscationPrefixLength, obfuscationSuffixLength) = MaskObfuscatedFile(storedPath);
            }
            else
            {
                CryptoService.EncryptFileToPath(key, child.SourcePath, storedPath, out contentNonce, out contentTag, progress);
            }

            manifest.Entries.Add(new StoredFolderEntry
            {
                OriginalName = originalName,
                OriginalExtension = originalExtension,
                OriginalLength = originalLength,
                OriginalLastWriteTime = originalLastWriteTime,
                IsFolder = false,
                StoredName = storedName,
                StorageMode = mode,
                ContentNonce = contentNonce,
                ContentTag = contentTag,
                ObfuscationNonce = obfuscationNonce,
                ObfuscationPrefixLength = obfuscationPrefixLength,
                ObfuscationSuffixLength = obfuscationSuffixLength
            });
        }

        return WriteFolderManifest(key, destinationPath, manifest);
    }

    private static void ExtractFolderTreeFromVault(byte[] key, string storedPath, string destinationPath)
    {
        Directory.CreateDirectory(destinationPath);
        var manifest = ReadFolderManifest(key, storedPath, "");
        foreach (var entry in manifest.Entries)
        {
            var sourcePath = Path.Combine(storedPath, entry.StoredName);
            var destination = Path.Combine(destinationPath, entry.OriginalName);
            if (entry.IsFolder)
            {
                ExtractFolderTreeFromVault(key, sourcePath, destination, entry.FolderManifestName);
                Directory.SetLastWriteTimeUtc(destination, entry.OriginalLastWriteTime.UtcDateTime);
                continue;
            }

            if (string.Equals(entry.StorageMode, FileStorageModes.Obfuscated, StringComparison.OrdinalIgnoreCase))
            {
                File.Copy(sourcePath, destination, false);
                ApplyObfuscationMask(destination, entry.ObfuscationNonce, entry.ObfuscationPrefixLength, entry.ObfuscationSuffixLength);
            }
            else
            {
                var tempRecord = new FileRecord
                {
                    ContentNonce = entry.ContentNonce,
                    ContentTag = entry.ContentTag
                };
                CryptoService.DecryptFileToPath(key, tempRecord, sourcePath, destination);
            }

            File.SetLastWriteTimeUtc(destination, entry.OriginalLastWriteTime.UtcDateTime);
        }
    }

    private static void ExtractFolderTreeFromVault(byte[] key, string storedPath, string destinationPath, string manifestName)
    {
        Directory.CreateDirectory(destinationPath);
        var manifest = ReadFolderManifest(key, storedPath, manifestName);
        foreach (var entry in manifest.Entries)
        {
            var sourcePath = Path.Combine(storedPath, entry.StoredName);
            var destination = Path.Combine(destinationPath, entry.OriginalName);
            if (entry.IsFolder)
            {
                ExtractFolderTreeFromVault(key, sourcePath, destination, entry.FolderManifestName);
                Directory.SetLastWriteTimeUtc(destination, entry.OriginalLastWriteTime.UtcDateTime);
                continue;
            }

            if (string.Equals(entry.StorageMode, FileStorageModes.Obfuscated, StringComparison.OrdinalIgnoreCase))
            {
                File.Copy(sourcePath, destination, false);
                ApplyObfuscationMask(destination, entry.ObfuscationNonce, entry.ObfuscationPrefixLength, entry.ObfuscationSuffixLength);
            }
            else
            {
                var tempRecord = new FileRecord
                {
                    ContentNonce = entry.ContentNonce,
                    ContentTag = entry.ContentTag
                };
                CryptoService.DecryptFileToPath(key, tempRecord, sourcePath, destination);
            }

            File.SetLastWriteTimeUtc(destination, entry.OriginalLastWriteTime.UtcDateTime);
        }
    }

    private static string WriteFolderManifest(byte[] key, string folderPath, StoredFolderManifest manifest)
    {
        var blob = CryptoService.EncryptJson(key, manifest);
        var manifestName = NewStoredItemName();
        AtomicWriteAllText(Path.Combine(folderPath, manifestName), JsonSerializer.Serialize(blob, JsonOptions.Default));
        return manifestName;
    }

    private static StoredFolderManifest ReadFolderManifest(byte[] key, string folderPath, string manifestName)
    {
        var manifestPath = Path.Combine(folderPath, string.IsNullOrWhiteSpace(manifestName) ? FolderManifestFileName : manifestName);
        var blob = JsonSerializer.Deserialize<EncryptedBlob>(File.ReadAllText(manifestPath), JsonOptions.Default)
                   ?? throw new InvalidOperationException("Klasör manifesti okunamadı.");
        return CryptoService.DecryptJson<StoredFolderManifest>(key, blob);
    }

    private static void WriteFolderManifest(byte[] key, string folderPath, string manifestName, StoredFolderManifest manifest)
    {
        var blob = CryptoService.EncryptJson(key, manifest);
        AtomicWriteAllText(Path.Combine(folderPath, manifestName), JsonSerializer.Serialize(blob, JsonOptions.Default));
    }

    private string ExtractFolderTreeFileToTemp(byte[] key, UserRecord user, FileRecord record, string relativeFilePath, string tempRoot)
    {
        var relativeDirectory = Path.GetDirectoryName(relativeFilePath) ?? "";
        var fileName = Path.GetFileName(relativeFilePath);
        var storedRoot = Path.Combine(GetUserFilesRoot(user.Id), record.StoredName);
        var location = ResolveFolderLocation(key, storedRoot, record.FolderManifestName, SplitRelativePath(relativeDirectory));
        var manifest = ReadFolderManifest(key, location.StoredPath, location.ManifestName);
        var entry = manifest.Entries.FirstOrDefault(item => !item.IsFolder && string.Equals(item.OriginalName, fileName, StringComparison.CurrentCultureIgnoreCase))
                    ?? throw new FileNotFoundException("Seçilen dosya manifest içinde bulunamadı.", fileName);

        var destination = Path.Combine(tempRoot, relativeFilePath);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        var sourcePath = Path.Combine(location.StoredPath, entry.StoredName);
        if (string.Equals(entry.StorageMode, FileStorageModes.Obfuscated, StringComparison.OrdinalIgnoreCase))
        {
            File.Copy(sourcePath, destination, false);
            ApplyObfuscationMask(destination, entry.ObfuscationNonce, entry.ObfuscationPrefixLength, entry.ObfuscationSuffixLength);
        }
        else
        {
            var tempRecord = new FileRecord
            {
                ContentNonce = entry.ContentNonce,
                ContentTag = entry.ContentTag
            };
            CryptoService.DecryptFileToPath(key, tempRecord, sourcePath, destination);
        }

        File.SetLastWriteTimeUtc(destination, entry.OriginalLastWriteTime.UtcDateTime);
        return destination;
    }

    private void SaveFolderTreeTempFileBack(UserRecord user, FileRecord record, string relativeFilePath, string tempPath, byte[] key)
    {
        if (!File.Exists(tempPath))
        {
            return;
        }

        var relativeDirectory = Path.GetDirectoryName(relativeFilePath) ?? "";
        var fileName = Path.GetFileName(relativeFilePath);
        var storedRoot = Path.Combine(GetUserFilesRoot(user.Id), record.StoredName);
        var location = ResolveFolderLocation(key, storedRoot, record.FolderManifestName, SplitRelativePath(relativeDirectory));
        var manifest = ReadFolderManifest(key, location.StoredPath, location.ManifestName);
        var entry = manifest.Entries.FirstOrDefault(item => !item.IsFolder && string.Equals(item.OriginalName, fileName, StringComparison.CurrentCultureIgnoreCase))
                    ?? throw new FileNotFoundException("Seçilen dosya manifest içinde bulunamadı.", fileName);

        var storedPath = Path.Combine(location.StoredPath, entry.StoredName);
        if (string.Equals(entry.StorageMode, FileStorageModes.Obfuscated, StringComparison.OrdinalIgnoreCase))
        {
            File.Copy(tempPath, storedPath, true);
            var (nonce, prefixLength, suffixLength) = MaskObfuscatedFile(storedPath);
            entry.ObfuscationNonce = nonce;
            entry.ObfuscationPrefixLength = prefixLength;
            entry.ObfuscationSuffixLength = suffixLength;
        }
        else
        {
            CryptoService.EncryptFileFromPathToPath(key, tempPath, storedPath, out var nonce, out var tag);
            entry.ContentNonce = nonce;
            entry.ContentTag = tag;
        }

        var info = new FileInfo(tempPath);
        entry.OriginalLength = info.Length;
        entry.OriginalLastWriteTime = new DateTimeOffset(DateTime.SpecifyKind(info.LastWriteTimeUtc, DateTimeKind.Utc));
        WriteFolderManifest(key, location.StoredPath, location.ManifestName, manifest);
        record.CipherLength = GetDirectorySize(storedRoot);
        SaveUser(user);
    }

    private static (string StoredPath, string ManifestName) ResolveFolderLocation(byte[] key, string storedRoot, string rootManifestName, IReadOnlyList<string> relativeSegments)
    {
        var currentPath = storedRoot;
        var currentManifestName = rootManifestName;
        foreach (var segment in relativeSegments)
        {
            var manifest = ReadFolderManifest(key, currentPath, currentManifestName);
            var entry = manifest.Entries.FirstOrDefault(item => item.IsFolder && string.Equals(item.OriginalName, segment, StringComparison.CurrentCultureIgnoreCase))
                        ?? throw new DirectoryNotFoundException($"Klasör bulunamadı: {segment}");
            currentPath = Path.Combine(currentPath, entry.StoredName);
            currentManifestName = entry.FolderManifestName;
        }

        return (currentPath, currentManifestName);
    }

    private static IReadOnlyList<string> SplitRelativePath(string relativePath)
    {
        return string.IsNullOrWhiteSpace(relativePath)
            ? []
            : relativePath.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries);
    }

    private static string CombineRelativePath(string basePath, string name)
    {
        return string.IsNullOrWhiteSpace(basePath) ? name : Path.Combine(basePath, name);
    }

    private static void CollectFolderTreeModes(byte[] key, string storedPath, string manifestName, string relativePath, Dictionary<string, FileAddMode> modes)
    {
        var manifest = ReadFolderManifest(key, storedPath, manifestName);
        foreach (var entry in manifest.Entries)
        {
            var childRelativePath = string.IsNullOrWhiteSpace(relativePath)
                ? entry.OriginalName
                : Path.Combine(relativePath, entry.OriginalName);

            if (entry.IsFolder)
            {
                CollectFolderTreeModes(key, Path.Combine(storedPath, entry.StoredName), entry.FolderManifestName, childRelativePath, modes);
            }
            else
            {
                modes[childRelativePath] = string.Equals(entry.StorageMode, FileStorageModes.Obfuscated, StringComparison.OrdinalIgnoreCase)
                    ? FileAddMode.Obfuscate
                    : FileAddMode.Encrypt;
            }
        }
    }

    private static void ApplyKnownModes(FolderImportPlan plan, string relativePath, Dictionary<string, FileAddMode> modes)
    {
        foreach (var child in plan.Children)
        {
            var childRelativePath = string.IsNullOrWhiteSpace(relativePath)
                ? child.Name
                : Path.Combine(relativePath, child.Name);

            if (child.IsFolder)
            {
                ApplyKnownModes(child, childRelativePath, modes);
            }
            else if (modes.TryGetValue(childRelativePath, out var mode))
            {
                child.Mode = mode;
            }
        }
    }

    private static FolderImportPlan BuildUniformFolderPlan(string sourcePath, FileAddMode mode)
    {
        var directory = new DirectoryInfo(sourcePath);
        var plan = new FolderImportPlan
        {
            SourcePath = sourcePath,
            Name = directory.Name,
            IsFolder = true,
            Mode = mode
        };

        foreach (var file in Directory.EnumerateFiles(sourcePath))
        {
            plan.Children.Add(new FolderImportPlan
            {
                SourcePath = file,
                Name = Path.GetFileName(file),
                IsFolder = false,
                Mode = mode
            });
        }

        foreach (var childDirectory in Directory.EnumerateDirectories(sourcePath))
        {
            plan.Children.Add(BuildUniformFolderPlan(childDirectory, mode));
        }

        return plan;
    }

    private static string NewStoredItemName() => $"{Guid.NewGuid():N}{StoredItemExtension}";

    private static (string Nonce, long PrefixLength, long SuffixLength) MaskObfuscatedFile(string path)
    {
        var length = new FileInfo(path).Length;
        if (length == 0)
        {
            return ("", 0, 0);
        }

        var prefixLength = Math.Min(length, ObfuscationMaskSize);
        var suffixLength = length > prefixLength
            ? Math.Min(length - prefixLength, ObfuscationMaskSize)
            : 0;
        var nonce = CryptoService.ToBase64(CryptoService.RandomBytes(CryptoService.KeySize));
        ApplyObfuscationMask(path, nonce, prefixLength, suffixLength);
        return (nonce, prefixLength, suffixLength);
    }

    private static void ApplyObfuscationMask(string path, string nonceBase64, long prefixLength, long suffixLength)
    {
        if (string.IsNullOrWhiteSpace(nonceBase64) || !File.Exists(path))
        {
            return;
        }

        var fileLength = new FileInfo(path).Length;
        if (fileLength == 0)
        {
            return;
        }

        var nonce = CryptoService.FromBase64(nonceBase64);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        if (prefixLength > 0)
        {
            TransformObfuscationRange(stream, nonce, 0, Math.Min(prefixLength, fileLength), 1);
        }

        if (suffixLength > 0)
        {
            var actualSuffixLength = Math.Min(suffixLength, Math.Max(0, fileLength - prefixLength));
            if (actualSuffixLength > 0)
            {
                TransformObfuscationRange(stream, nonce, fileLength - actualSuffixLength, actualSuffixLength, 2);
            }
        }

        CryptographicOperations.ZeroMemory(nonce);
    }

    private static void TransformObfuscationRange(FileStream stream, byte[] nonce, long offset, long length, byte region)
    {
        if (length <= 0)
        {
            return;
        }

        var buffer = new byte[length];
        stream.Position = offset;
        stream.ReadExactly(buffer);
        XorWithMask(buffer, nonce, region);
        stream.Position = offset;
        stream.Write(buffer);
        stream.Flush(true);
        CryptographicOperations.ZeroMemory(buffer);
    }

    private static void XorWithMask(byte[] buffer, byte[] nonce, byte region)
    {
        Span<byte> counterBytes = stackalloc byte[sizeof(ulong)];
        var seed = new byte[nonce.Length + 1 + sizeof(ulong)];
        nonce.CopyTo(seed, 0);
        seed[nonce.Length] = region;

        ulong counter = 0;
        var offset = 0;
        while (offset < buffer.Length)
        {
            BitConverter.GetBytes(counter++).CopyTo(counterBytes);
            counterBytes.CopyTo(seed.AsSpan(nonce.Length + 1));
            var mask = SHA256.HashData(seed);
            var take = Math.Min(mask.Length, buffer.Length - offset);
            for (var i = 0; i < take; i++)
            {
                buffer[offset + i] ^= mask[i];
            }

            CryptographicOperations.ZeroMemory(mask);
            offset += take;
        }

        CryptographicOperations.ZeroMemory(seed);
    }

    public void SaveUser(UserRecord user)
    {
        var path = GetUserPath(user.Id);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        AtomicWriteAllText(path, JsonSerializer.Serialize(user, JsonOptions.Default));
    }

    private static void AtomicWriteAllText(string path, string contents)
    {
        var directory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(directory);
        var tempPath = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        File.WriteAllText(tempPath, contents);
        if (File.Exists(path))
        {
            try
            {
                File.Replace(tempPath, path, null, true);
            }
            catch (IOException)
            {
                File.Move(tempPath, path, true);
            }
            catch (UnauthorizedAccessException)
            {
                File.Move(tempPath, path, true);
            }
        }
        else
        {
            File.Move(tempPath, path);
        }
    }

    private string GetUserRoot(string userId) => Path.Combine(UsersRoot, userId);

    private string GetUserFilesRoot(string userId)
    {
        var path = Path.Combine(GetUserRoot(userId), "files");
        Directory.CreateDirectory(path);
        return path;
    }

    private string GetUserPath(string userId) => Path.Combine(GetUserRoot(userId), "user.json");

    private static bool IsObfuscated(FileRecord record)
    {
        return string.Equals(record.StorageMode, FileStorageModes.Obfuscated, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsFolderTree(FileRecord record)
    {
        return string.Equals(record.StorageMode, FileStorageModes.FolderTree, StringComparison.OrdinalIgnoreCase);
    }

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

    private static void CopyDirectory(string sourcePath, string destinationPath)
    {
        Directory.CreateDirectory(destinationPath);
        foreach (var directory in Directory.EnumerateDirectories(sourcePath, "*", SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(Path.Combine(destinationPath, Path.GetRelativePath(sourcePath, directory)));
        }

        foreach (var file in Directory.EnumerateFiles(sourcePath, "*", SearchOption.AllDirectories))
        {
            var destinationFile = Path.Combine(destinationPath, Path.GetRelativePath(sourcePath, file));
            Directory.CreateDirectory(Path.GetDirectoryName(destinationFile)!);
            File.Copy(file, destinationFile, true);
        }
    }

    private static void CopyFileWithProgress(string sourcePath, string destinationPath, bool overwrite, IProgress<long>? progress)
    {
        const int bufferSize = 4 * 1024 * 1024;
        var mode = overwrite ? FileMode.Create : FileMode.CreateNew;
        var buffer = new byte[bufferSize];
        using var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize);
        using var destination = new FileStream(destinationPath, mode, FileAccess.Write, FileShare.None, bufferSize);

        int read;
        while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
        {
            destination.Write(buffer, 0, read);
            progress?.Report(read);
        }

        destination.Flush(true);
        CryptographicOperations.ZeroMemory(buffer);
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

    private static void ShredDirectory(string path, IProgress<long>? progress = null)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            ShredFile(file, progress);
        }

        foreach (var dir in Directory.EnumerateDirectories(path, "*", SearchOption.AllDirectories)
                     .OrderByDescending(dir => dir.Length))
        {
            try { Directory.Delete(dir, false); } catch { }
        }

        try { Directory.Delete(path, false); } catch { }
    }

    private static void ShredFile(string path, IProgress<long>? progress = null)
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
                progress?.Report(write);
                remaining -= write;
            }

            stream.Flush(true);
        }

        CryptographicOperations.ZeroMemory(buffer);
        File.Delete(path);
    }

    private static void TryShredFile(string path, IProgress<long>? progress = null)
    {
        try
        {
            if (File.Exists(path))
            {
                ShredFile(path, progress);
            }
        }
        catch
        {
            TryDelete(path);
        }
    }

    private static void TryShredDirectory(string path, IProgress<long>? progress = null)
    {
        try
        {
            if (Directory.Exists(path))
            {
                ShredDirectory(path, progress);
            }
        }
        catch
        {
            try { Directory.Delete(path, true); } catch { }
        }
    }
}
