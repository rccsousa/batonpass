using System.Runtime.Versioning;
using System.Text;
using BatonPass.Windows.Agent.Crypto;
using BatonPass.Windows.Agent.Native;
using BatonPass.Windows.Agent.Relay;
using BatonPass.Windows.Agent.State;

namespace BatonPass.Windows.Agent;

/// Wires clipboard watch -> seal -> relay send, and relay receive -> receiver
/// state machine -> clipboard write, with loop suppression on the write side.
[SupportedOSPlatform("windows")]
public sealed class AgentLoop
{
    private readonly byte[] _key;
    private readonly AgentConfig _config;
    private readonly ReceiverStateMachine _receiver;
    private readonly PhoenixRelayClient _relay;
    private readonly ClipboardWatcher _watcher;
    private long _encryptionCount;

    public AgentLoop(
        byte[] key,
        AgentConfig config,
        ReceiverStateMachine receiver,
        PhoenixRelayClient relay,
        ClipboardWatcher watcher)
    {
        _key = key;
        _config = config;
        _receiver = receiver;
        _relay = relay;
        _watcher = watcher;

        _watcher.ExternalChangeDetected += OnLocalCopy;
        _relay.FrameReceived += OnFrameReceived;
        _relay.Diagnostic += SafeLog.Warn;
    }

    /// SPEC.md §6: "each device counts its own encryptions and surfaces the
    /// total. It does not stop sending" — observability only, never a gate.
    public long EncryptionCount => Interlocked.Read(ref _encryptionCount);

    private async void OnLocalCopy(string text)
    {
        try
        {
            byte[] plaintext = Encoding.UTF8.GetBytes(text);

            // SPEC.md §3: a sender whose plaintext exceeds the max MUST reject
            // and report the item. Never fragment.
            if (plaintext.Length > Envelope.MaxPlaintext)
            {
                SafeLog.Warn($"clipboard item too large to send ({plaintext.Length} bytes > {Envelope.MaxPlaintext}); refusing, not fragmenting");
                return;
            }

            ulong ts = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            byte[] frame = Envelope.SealNew(_key, _config.Epoch, _config.SenderId, ts, plaintext, out _);
            Interlocked.Increment(ref _encryptionCount);

            if (!_relay.IsConnected)
            {
                SafeLog.Warn("relay not connected; dropping local copy (best effort, no local send queue)");
                return;
            }

            await _relay.SendFrameAsync(frame, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            SafeLog.Error($"failed to seal/send local clipboard change: {ex.GetType().Name}");
        }
    }

    private void OnFrameReceived(byte[] frame)
    {
        AcceptOutcome outcome;
        try
        {
            outcome = _receiver.TryAccept(frame);
        }
        catch (Exception ex)
        {
            SafeLog.Error($"receiver threw on an inbound frame: {ex.GetType().Name}");
            return;
        }

        if (!outcome.IsAccepted)
        {
            SafeLog.Info($"rejected inbound frame: {outcome.Status}");
            return;
        }

        try
        {
            string text = Encoding.UTF8.GetString(outcome.Plaintext!);
            ClipboardService.WriteText(text);
            _watcher.NotifySelfWrite(text);
            SafeLog.Info($"accepted inbound frame and wrote {text.Length} chars to the clipboard");

            // Length-only verification, never content: confirms the write this
            // process just made is actually the one a read sees back. Catches
            // window-station isolation (a non-interactive process can land in a
            // clipboard no other process, including a test probe, shares — see
            // FINDINGS.md) without ever logging what was written.
            string? readback = ClipboardService.ReadText();
            if (readback is null || readback.Length != text.Length)
                SafeLog.Warn($"post-write clipboard readback did not match (readback {(readback is null ? "null" : $"{readback.Length} chars")} vs wrote {text.Length} chars)");
        }
        catch (Exception ex)
        {
            SafeLog.Error($"accepted frame but clipboard write failed: {ex.GetType().Name}");
        }
    }
}
