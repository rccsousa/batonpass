using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace BatonPass.Windows.Agent.State;

/// <summary>
/// Group key storage. SPEC.md §6: "DPAPI with machine scope on Windows",
/// never backed up, never transported over BatonPass itself — import is out of
/// band (Program.cs's `import-key` command), matching the rekey procedure.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class KeyStore(string path)
{
    public bool Exists => File.Exists(path);

    public byte[] Load()
    {
        byte[] protectedBytes = File.ReadAllBytes(path);
        byte[] key = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.LocalMachine);
        if (key.Length != 32)
            throw new InvalidDataException("stored group key is not 32 bytes");
        return key;
    }

    public void Save(ReadOnlySpan<byte> key)
    {
        if (key.Length != 32) throw new ArgumentException("group key must be 32 bytes");
        byte[] protectedBytes = ProtectedData.Protect(key.ToArray(), null, DataProtectionScope.LocalMachine);

        string dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);
        string tmp = path + ".tmp";
        File.WriteAllBytes(tmp, protectedBytes);
        File.Move(tmp, path, overwrite: true);
    }
}
