using System.Text.Json.Serialization;

namespace UsbSecureVault;

public sealed class VaultConfig
{
    public string VaultId { get; set; } = "";
    public bool MasterPasswordEnabled { get; set; } = true;
    public int KdfIterations { get; set; } = 600_000;
    public string MasterSalt { get; set; } = "";
    public string MasterHash { get; set; } = "";
    public string MasterHint { get; set; } = "";
    public string EmergencyInfo { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
}

public sealed class UserRecord
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public bool PasswordEnabled { get; set; } = true;
    public int KdfIterations { get; set; } = 600_000;
    public string PasswordSalt { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string PasswordHint { get; set; } = "";
    public string WrappedKeyNonce { get; set; } = "";
    public string WrappedKeyTag { get; set; } = "";
    public string WrappedKeyCiphertext { get; set; } = "";
    public List<FileRecord> Files { get; set; } = [];

    [JsonIgnore]
    public byte[]? UnlockedKey { get; set; }
}

public sealed class FileRecord
{
    public string Id { get; set; } = "";
    public string StoredName { get; set; } = "";
    public string FolderManifestName { get; set; } = "";
    public string StorageMode { get; set; } = FileStorageModes.Encrypted;
    public string MetadataNonce { get; set; } = "";
    public string MetadataTag { get; set; } = "";
    public string MetadataCiphertext { get; set; } = "";
    public string ContentNonce { get; set; } = "";
    public string ContentTag { get; set; } = "";
    public string ObfuscationNonce { get; set; } = "";
    public long ObfuscationPrefixLength { get; set; }
    public long ObfuscationSuffixLength { get; set; }
    public long CipherLength { get; set; }
    public DateTimeOffset AddedAt { get; set; }
}

public sealed class FileMetadata
{
    public string OriginalName { get; set; } = "";
    public string OriginalExtension { get; set; } = "";
    public string OriginalRelativeDirectory { get; set; } = "";
    public long OriginalLength { get; set; }
    public DateTimeOffset OriginalLastWriteTime { get; set; }
    public bool IsFolder { get; set; }
}

public static class FileStorageModes
{
    public const string Encrypted = "Encrypted";
    public const string Obfuscated = "Obfuscated";
    public const string FolderTree = "FolderTree";
}

public sealed class FolderImportPlan
{
    public required string SourcePath { get; init; }
    public required string Name { get; init; }
    public bool IsFolder { get; init; }
    public FileAddMode Mode { get; set; } = FileAddMode.Encrypt;
    public List<FolderImportPlan> Children { get; init; } = [];
}

public sealed class StoredFolderManifest
{
    public List<StoredFolderEntry> Entries { get; set; } = [];
}

public sealed class StoredFolderEntry
{
    public string OriginalName { get; set; } = "";
    public string OriginalExtension { get; set; } = "";
    public long OriginalLength { get; set; }
    public DateTimeOffset OriginalLastWriteTime { get; set; }
    public bool IsFolder { get; set; }
    public string StoredName { get; set; } = "";
    public string FolderManifestName { get; set; } = "";
    public string StorageMode { get; set; } = FileStorageModes.Encrypted;
    public string ContentNonce { get; set; } = "";
    public string ContentTag { get; set; } = "";
    public string ObfuscationNonce { get; set; } = "";
    public long ObfuscationPrefixLength { get; set; }
    public long ObfuscationSuffixLength { get; set; }
}

public sealed class UserListItem
{
    public required string Id { get; init; }
    public required string Name { get; init; }
}

public sealed class FileListItem
{
    public required FileRecord Record { get; init; }
    public required FileMetadata Metadata { get; init; }
    public string Name => Metadata.IsFolder ? $"[Klasör] {Metadata.OriginalName}" : Metadata.OriginalName;
    public string ModeText => Record.StorageMode == FileStorageModes.Obfuscated
        ? "Boz"
        : Record.StorageMode == FileStorageModes.FolderTree ? "Klasör Ağacı" : "Şifreli";
    public string SizeText => FormatBytes(Metadata.OriginalLength);
    public string AddedText => Record.AddedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm");

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)bytes;
        var index = 0;
        while (value >= 1024 && index < units.Length - 1)
        {
            value /= 1024;
            index++;
        }

        return index == 0 ? $"{bytes} B" : $"{value:0.##} {units[index]}";
    }
}

public sealed class FileOperationProgress
{
    public string Message { get; init; } = "";
    public long CompletedBytes { get; init; }
    public long TotalBytes { get; init; }

    public double Percent => TotalBytes <= 0
        ? 0
        : Math.Min(100, Math.Max(0, CompletedBytes * 100.0 / TotalBytes));
}

public sealed class VaultFolderItem
{
    public required string Name { get; init; }
    public required string RelativePath { get; init; }
    public bool IsFolder { get; init; }
    public long Length { get; init; }
    public DateTimeOffset LastWriteTime { get; init; }
    public string StorageMode { get; init; } = FileStorageModes.Encrypted;
    public string TypeText => IsFolder ? "Klasör" : StorageMode == FileStorageModes.Obfuscated ? "Boz" : "Şifreli";
    public string SizeText => IsFolder ? "" : FormatBytes(Length);
    public string ModifiedText => LastWriteTime.LocalDateTime.ToString("yyyy-MM-dd HH:mm");

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var value = (double)bytes;
        var index = 0;
        while (value >= 1024 && index < units.Length - 1)
        {
            value /= 1024;
            index++;
        }

        return index == 0 ? $"{bytes} B" : $"{value:0.##} {units[index]}";
    }
}
