using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using BatonPass.Windows.Agent.Native;

namespace BatonPass.Windows.Agent;

/// <summary>
/// Polls GetClipboardSequenceNumber per the S3-evidenced adapter contract
/// (spikes/s3-windows-clipboard/FINDINGS.md: "poll... treat any strictly
/// increasing value as a change. Never assume +1" — S3 measured a delta of 5
/// per write, including this process's own writes).
///
/// Loop suppression is content-hash based, not sequence-number based: this
/// agent's own write always bumps the sequence number, and that bump is
/// expected to fire — what must not happen is re-sending that value to the
/// relay.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ClipboardWatcher(TimeSpan pollInterval)
{
    private int _lastSeq = ClipboardService.GetSequenceNumber();
    private byte[]? _lastSelfWrittenHash;

    public event Action<string>? ExternalChangeDetected;

    public void NotifySelfWrite(string text)
    {
        _lastSelfWrittenHash = Hash(text);
    }

    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(pollInterval, ct).ConfigureAwait(false);
            Poll();
        }
    }

    /// Exposed separately so tests/CLI tooling can drive one poll deterministically.
    public void Poll()
    {
        int seq = ClipboardService.GetSequenceNumber();
        if (seq <= _lastSeq) return; // strictly increasing only — never previous+1
        _lastSeq = seq;

        string? text = ClipboardService.ReadText();
        if (string.IsNullOrEmpty(text)) return; // non-text clipboard content: not our concern

        var hash = Hash(text);
        if (_lastSelfWrittenHash is not null && hash.AsSpan().SequenceEqual(_lastSelfWrittenHash))
            return; // our own write's own change notification

        ExternalChangeDetected?.Invoke(text);
    }

    private static byte[] Hash(string text) => SHA256.HashData(Encoding.UTF8.GetBytes(text));
}
