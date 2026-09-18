using BatonPass.Windows.Agent.Native;
using BatonPass.Windows.Agent.Relay;
using BatonPass.Windows.Agent.State;
using System.Security.Principal;

namespace BatonPass.Windows.Agent;

internal static class Program
{
    public const string NonInteractiveTestEnvVar = "BATONPASS_ALLOW_NONINTERACTIVE_TEST";
    public const int DedupCacheCapacity = 4096;
    public static readonly TimeSpan ClipboardPollInterval = TimeSpan.FromMilliseconds(500);

    public static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("batonpass-agent only runs on Windows (native Win32 clipboard, DPAPI).");
            return 1;
        }

        string command = args.Length > 0 && !args[0].StartsWith("--", StringComparison.Ordinal) ? args[0] : "run";

        return command switch
        {
            "run" => await RunAsync(args).ConfigureAwait(false),
            "import-key" => ImportKey(args),
            "resume-after-clock-correction" => ResumeAfterClockCorrection(),
            "status" => Status(),
            "relay-smoke-test" => await RelaySmokeTestAsync(args).ConfigureAwait(false),
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.Error.WriteLine(
            """
            usage:
              batonpass-agent run [--allow-noninteractive]
              batonpass-agent import-key --key <64-hex-chars> --relay <wss://...> --group <id> --sender-id <uint> --epoch <uint>
              batonpass-agent resume-after-clock-correction
              batonpass-agent status
              batonpass-agent relay-smoke-test send --relay <ws://host:port/socket/websocket?vsn=2.0.0> --group <id> [--message <text>]
              batonpass-agent relay-smoke-test listen --relay <ws://...> --group <id> [--timeout-sec <n>]
                TEST ONLY: connectivity/wire-protocol check against a live relay. Seals
                with a public test-vector key (crypto/vectors.json), never the real
                group key. Does not touch the clipboard or check the session.
            """);
        return 2;
    }

    // crypto/vectors.json's keyHex — a public conformance-test key, never used
    // for anything but this connectivity smoke test.
    private static readonly byte[] RelaySmokeTestKey =
        Convert.FromHexString("4f8a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a");

    private static async Task<int> RelaySmokeTestAsync(string[] args)
    {
        string mode = args.Length > 1 ? args[1] : "";
        string? relayUri = GetOpt(args, "--relay");
        string? group = GetOpt(args, "--group");
        if (relayUri is null || group is null || mode is not ("send" or "listen"))
            return Usage();

        await using var client = new PhoenixRelayClient(new Uri(relayUri), group);
        client.Diagnostic += SafeLog.Warn;

        byte[] key = RelaySmokeTestKey;
        if (GetOpt(args, "--key") is { } keyHex) key = Convert.FromHexString(keyHex);
        uint epoch = uint.TryParse(GetOpt(args, "--epoch"), out var e) ? e : 1;
        uint senderId = uint.TryParse(GetOpt(args, "--sender-id"), out var s) ? s : 0xFEED_FACE;

        if (mode == "send")
        {
            string message = GetOpt(args, "--message") ?? "batonpass relay-smoke-test";
            using var joinCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await client.ConnectAndJoinAsync(joinCts.Token).ConfigureAwait(false);
            SafeLog.Info($"relay-smoke-test send: joined clipboard:{group}");

            byte[] plaintext = System.Text.Encoding.UTF8.GetBytes(message);
            ulong ts = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            byte[] frame = Crypto.Envelope.SealNew(key, epoch, senderId, ts, plaintext, out _);

            using var sendCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await client.SendFrameAsync(frame, sendCts.Token).ConfigureAwait(false);
            SafeLog.Info($"relay-smoke-test send: pushed a {frame.Length}-byte frame");

            await Task.Delay(500).ConfigureAwait(false); // let the send flush before closing
            return 0;
        }

        // listen
        int timeoutSec = int.TryParse(GetOpt(args, "--timeout-sec"), out var t) ? t : 20;
        var received = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.FrameReceived += frame =>
        {
            bool decrypts = Crypto.Envelope.CheckLengthAndVersion(frame) == Crypto.Envelope.RejectReason.None
                && Crypto.Envelope.TryDecrypt(key, frame, out _);
            SafeLog.Info($"relay-smoke-test listen: received a {frame.Length}-byte frame, decrypts_with_given_key={decrypts}");
            received.TrySetResult(frame.Length);
        };

        using var listenJoinCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await client.ConnectAndJoinAsync(listenJoinCts.Token).ConfigureAwait(false);
        SafeLog.Info($"relay-smoke-test listen: joined clipboard:{group}, waiting up to {timeoutSec}s for a frame");

        var completed = await Task.WhenAny(received.Task, Task.Delay(TimeSpan.FromSeconds(timeoutSec))).ConfigureAwait(false);
        if (completed != received.Task)
        {
            SafeLog.Warn("relay-smoke-test listen: timed out, no frame received");
            return 1;
        }
        return 0;
    }

    private static async Task<int> RunAsync(string[] args)
    {
        bool allowNonInteractive = args.Contains("--allow-noninteractive");

        var check = SessionGuard.Check();
        if (!check.IsInteractive)
        {
            bool testOverride = allowNonInteractive
                && Environment.GetEnvironmentVariable(NonInteractiveTestEnvVar) == "1";

            if (!testOverride)
            {
                SafeLog.Error(
                    $"refusing to run: process session {check.ProcessSessionId} != active console session " +
                    $"{check.ActiveConsoleSessionId}. Native clipboard calls would succeed here against a " +
                    "window-station-local clipboard no user can see (spikes/s3-windows-clipboard/FINDINGS.md). " +
                    $"Run this interactively, or for testing only set {NonInteractiveTestEnvVar}=1 and pass --allow-noninteractive.");
                return 1;
            }

            SafeLog.Warn(
                "TEST-ONLY OVERRIDE: running in a non-interactive session " +
                $"(process session {check.ProcessSessionId} != active console session {check.ActiveConsoleSessionId}). " +
                "Clipboard writes below will not be visible to any real user.");
        }

        var config = AgentConfig.Load(Paths.Config);
        if (config is null)
        {
            SafeLog.Error($"no config at {Paths.Config}; run `import-key` first.");
            return 1;
        }

        var keyStore = new KeyStore(Paths.KeyFile);
        if (!keyStore.Exists)
        {
            SafeLog.Error($"no key at {Paths.KeyFile}; run `import-key` first.");
            return 1;
        }
        byte[] key = keyStore.Load();

        var persistence = new WindowsDedupPersistence(Paths.DedupState);
        var anchor = new FileCounterAnchor(Paths.CounterAnchor);
        var receiver = new ReceiverStateMachine(
            key,
            config.Epoch,
            DedupCacheCapacity,
            persistence,
            anchor,
            () => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

        if (receiver.IsTripped)
        {
            SafeLog.Error(
                "receiver state is TRIPPED (corrupt/missing dedup state, or a detected clock/counter rollback). " +
                "Refusing to accept inbound frames until an operator runs `resume-after-clock-correction`. " +
                "Sending local clipboard changes still works.");
        }

        var relay = new PhoenixRelayClient(new Uri(config.RelayUri), config.GroupId);
        var watcher = new ClipboardWatcher(ClipboardPollInterval);
        _ = new AgentLoop(key, config, receiver, relay, watcher);

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        SafeLog.Info($"batonpass-agent running: group={config.GroupId} sender={config.SenderId} epoch={config.Epoch}");
        SafeLog.Warn(
            "Win+V clipboard history note: exclusion formats are set on every write, but pre-existing history " +
            "entries from before this agent ran are untouched (spikes/s3-windows-clipboard/FINDINGS.md).");

        var watcherTask = watcher.RunAsync(cts.Token);
        var relayTask = RunRelayWithReconnectAsync(relay, cts.Token);

        await Task.WhenAny(watcherTask, relayTask).ConfigureAwait(false);
        await cts.CancelAsync().ConfigureAwait(false);
        return 0;
    }

    private static async Task RunRelayWithReconnectAsync(PhoenixRelayClient relay, CancellationToken ct)
    {
        var backoff = TimeSpan.FromSeconds(1);
        var maxBackoff = TimeSpan.FromSeconds(30);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await relay.RunUntilDisconnectedAsync(ct).ConfigureAwait(false);
                backoff = TimeSpan.FromSeconds(1);
                SafeLog.Warn("relay connection dropped; reconnecting");
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                SafeLog.Warn($"relay connection failed: {ex.GetType().Name}; retrying in {backoff.TotalSeconds:0}s");
            }

            try
            {
                await Task.Delay(backoff, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            backoff = TimeSpan.FromSeconds(Math.Min(backoff.TotalSeconds * 2, maxBackoff.TotalSeconds));
        }
    }

    private static int ImportKey(string[] args)
    {
        string? keyHex = GetOpt(args, "--key");
        string? relayUri = GetOpt(args, "--relay");
        string? group = GetOpt(args, "--group");
        string? senderIdStr = GetOpt(args, "--sender-id");
        string? epochStr = GetOpt(args, "--epoch");

        if (keyHex is null || relayUri is null || group is null || senderIdStr is null || epochStr is null)
            return Usage();

        byte[] key;
        try
        {
            key = Convert.FromHexString(keyHex);
        }
        catch (FormatException)
        {
            SafeLog.Error("--key must be hex");
            return 1;
        }
        if (key.Length != 32)
        {
            SafeLog.Error("--key must decode to exactly 32 bytes");
            return 1;
        }

        if (!uint.TryParse(senderIdStr, out uint senderId) || !uint.TryParse(epochStr, out uint epoch))
        {
            SafeLog.Error("--sender-id and --epoch must be uint32");
            return 1;
        }

        new KeyStore(Paths.KeyFile).Save(key);
        Array.Clear(key);

        new AgentConfig { RelayUri = relayUri, GroupId = group, SenderId = senderId, Epoch = epoch }.Save(Paths.Config);

        SafeLog.Info($"imported key and config under {Paths.Root} (group={group}, sender={senderId}, epoch={epoch})");
        return 0;
    }

    private static int ResumeAfterClockCorrection()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            SafeLog.Error(
                "refusing to resume while elevated: rewriting dedup state from an elevated process can replace " +
                "its creator-owner ACL and leave the limited scheduled task unable to persist state. Run this " +
                "command from a non-admin interactive shell as the account that runs the BatonPass task.");
            return 1;
        }

        var config = AgentConfig.Load(Paths.Config);
        if (config is null)
        {
            SafeLog.Error("no config; nothing to resume");
            return 1;
        }

        var persistence = new WindowsDedupPersistence(Paths.DedupState);
        var anchor = new FileCounterAnchor(Paths.CounterAnchor);
        // This command never decrypts anything (it only flips the tripped flag
        // and flushes the dedup cache), so a placeholder key is fine here.
        var placeholderKey = new byte[32];
        var receiver = new ReceiverStateMachine(
            placeholderKey,
            config.Epoch,
            DedupCacheCapacity,
            persistence,
            anchor,
            () => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

        receiver.ResumeAfterClockCorrection(DedupCacheCapacity);
        SafeLog.Info("dedup cache flushed and tripped state cleared. Restart the agent to resume receiving.");
        return 0;
    }

    private static int Status()
    {
        var check = SessionGuard.Check();
        Console.WriteLine($"interactive session: {check.IsInteractive}");
        Console.WriteLine($"  process session={check.ProcessSessionId} active console session={check.ActiveConsoleSessionId}");
        Console.WriteLine($"config present: {File.Exists(Paths.Config)}");
        Console.WriteLine($"key present: {File.Exists(Paths.KeyFile)}");
        Console.WriteLine($"dedup state present: {File.Exists(Paths.DedupState)}");
        Console.WriteLine($"counter anchor present: {File.Exists(Paths.CounterAnchor)}");
        return 0;
    }

    private static string? GetOpt(string[] args, string name)
    {
        int i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }
}
