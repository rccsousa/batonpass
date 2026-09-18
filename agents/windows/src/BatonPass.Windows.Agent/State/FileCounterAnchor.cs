using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;

namespace BatonPass.Windows.Agent.State;

/// <summary>
/// Independent monotonic high-water mark for the acceptance counter (§6/T2-F5),
/// deliberately stored at a different path than the dedup cache file so that
/// restoring one from an old backup without the other is still detectable.
///
/// Caveat (worth stating plainly, not silently assuming solved): this defends
/// against restoring one file/directory from an old snapshot, which is the
/// scenario SPEC.md §6 describes. It cannot defend against a restore that
/// rolls the whole machine back atomically (e.g. a VM snapshot revert) — both
/// stores would roll back together. A hardware monotonic counter (TPM) would be
/// needed for that and is out of scope here.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class FileCounterAnchor(string path) : ICounterAnchor
{
    private sealed class AnchorDto
    {
        public long HighWaterMark { get; set; }
        public bool Tripped { get; set; }
    }

    public long? ReadHighWaterMark() => ReadDto()?.HighWaterMark;

    public void WriteHighWaterMark(long value)
    {
        var dto = ReadDto() ?? new AnchorDto();
        dto.HighWaterMark = value;
        WriteDto(dto);
    }

    public bool ReadTripped() => ReadDto()?.Tripped ?? false;

    public void WriteTripped(bool tripped)
    {
        var dto = ReadDto() ?? new AnchorDto();
        dto.Tripped = tripped;
        WriteDto(dto);
    }

    private AnchorDto? ReadDto()
    {
        if (!File.Exists(path)) return null;
        byte[] protectedBytes = File.ReadAllBytes(path);
        byte[] plain = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.LocalMachine);
        return JsonSerializer.Deserialize<AnchorDto>(plain)
            ?? throw new InvalidDataException("counter anchor file parsed to null");
    }

    private void WriteDto(AnchorDto dto)
    {
        byte[] plain = JsonSerializer.SerializeToUtf8Bytes(dto);
        byte[] protectedBytes = ProtectedData.Protect(plain, null, DataProtectionScope.LocalMachine);

        string dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);
        string tmp = path + ".tmp";
        File.WriteAllBytes(tmp, protectedBytes);
        File.Move(tmp, path, overwrite: true);
    }
}
