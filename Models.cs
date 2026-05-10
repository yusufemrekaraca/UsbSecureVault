using System.Text.Json.Serialization;

namespace UsbSecureVault;

public sealed class VaultConfig
{
    public string VaultId { get; set; } = "";
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
    public string StorageMode { get; set; } = FileStorageModes.Encrypted;
    public string MetadataNonce { get; set; } = "";
    public string MetadataTag { get; set; } = "";
    public string MetadataCiphertext { get; set; } = "";
    public string ContentNonce { get; set; } = "";
    public string ContentTag { get; set; } = "";
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
    public string ModeText => Record.StorageMode == FileStorageModes.Obfuscated ? "Boz" : "Şifreli";
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
