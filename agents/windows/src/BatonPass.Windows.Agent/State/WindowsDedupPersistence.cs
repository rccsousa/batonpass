using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using BatonPass.Windows.Agent.Crypto;

namespace BatonPass.Windows.Agent.State;

/// <summary>
/// Dedup cache persistence. DPAPI machine scope (SPEC.md §6: "non-backed-up and
/// device-local... DPAPI with machine scope on Windows"). A decrypt or parse
/// failure propagates as an exception — the caller (ReceiverStateMachine) is
/// what decides that means "fail closed", not this class.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsDedupPersistence(string path) : IDedupPersistence
{
    private sealed class EntryDto
    {
        public uint Epoch { get; set; }
        public uint SenderId { get; set; }
        public string EventIdHex { get; set; } = "";
        public long ExpiresAtMs { get; set; }
    }

    private sealed class SnapshotDto
    {
        public List<EntryDto> Entries { get; set; } = [];
        public long AcceptanceCounter { get; set; }
        public long LastObservedNowMs { get; set; }
    }

    public DedupSnapshot? Load()
    {
        if (!File.Exists(path)) return null;

        byte[] protectedBytes = File.ReadAllBytes(path);
        byte[] plainBytes = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.LocalMachine);
        var dto = JsonSerializer.Deserialize<SnapshotDto>(plainBytes)
            ?? throw new InvalidDataException("dedup state file parsed to null");

        var entries = new Dictionary<DedupKey, long>(dto.Entries.Count);
        foreach (var e in dto.Entries)
        {
            var eventId = new EventId(Convert.FromHexString(e.EventIdHex));
            entries[new DedupKey(e.Epoch, e.SenderId, eventId)] = e.ExpiresAtMs;
        }
        return new DedupSnapshot(entries, dto.AcceptanceCounter, dto.LastObservedNowMs);
    }

    public void Persist(DedupSnapshot snapshot)
    {
        var dto = new SnapshotDto
        {
            AcceptanceCounter = snapshot.AcceptanceCounter,
            LastObservedNowMs = snapshot.LastObservedNowMs,
            Entries = snapshot.Entries
                .Select(kv => new EntryDto
                {
                    Epoch = kv.Key.Epoch,
                    SenderId = kv.Key.SenderId,
                    EventIdHex = kv.Key.EventId.ToString(),
                    ExpiresAtMs = kv.Value,
                })
                .ToList(),
        };

        byte[] plainBytes = JsonSerializer.SerializeToUtf8Bytes(dto);
        byte[] protectedBytes = ProtectedData.Protect(plainBytes, null, DataProtectionScope.LocalMachine);

        string dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);
        string tmp = path + ".tmp";
        File.WriteAllBytes(tmp, protectedBytes);
        File.Move(tmp, path, overwrite: true);
    }
}
