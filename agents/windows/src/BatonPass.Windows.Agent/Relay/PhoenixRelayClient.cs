using System.Net.WebSockets;
using System.Text;
using System.Text.Json;

namespace BatonPass.Windows.Agent.Relay;

/// <summary>
/// Phoenix channel client for relay/CONTRACT.md's `clipboard:&lt;group_id&gt;`
/// topic. Control messages (join, heartbeat, replies) are the standard Phoenix
/// JSON array protocol over text frames; the "frame" push/broadcast carrying
/// the envelope is binary, encoded per <see cref="PhoenixWireCodec"/>.
///
/// The relay never echoes to the sender (CONTRACT.md §5) and is best-effort
/// with no catch-up — this client does not queue sends while disconnected, it
/// just fails the individual send and lets the caller decide (the agent logs
/// and moves on; a missed relay delivery is an accepted loss per contract).
/// </summary>
public sealed class PhoenixRelayClient : IAsyncDisposable
{
    private static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(25);

    private readonly Uri _uri;
    private readonly string _topic;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly Dictionary<string, TaskCompletionSource<JsonElement>> _pendingReplies = new();

    private ClientWebSocket? _ws;
    private string? _joinRef;
    private long _refCounter;
    private CancellationTokenSource? _loopCts;
    private Task? _receiveLoop;
    private Task? _heartbeatLoop;

    public event Action<byte[]>? FrameReceived;
    public event Action<string>? Diagnostic;

    public PhoenixRelayClient(Uri relayUri, string groupId)
    {
        _uri = relayUri;
        _topic = $"clipboard:{groupId}";
    }

    public bool IsConnected => _ws?.State == WebSocketState.Open;

    /// <paramref name="ct"/> bounds only the connect+join handshake (e.g. a
    /// caller-supplied timeout). The receive/heartbeat loops that follow get
    /// their own independent lifetime, torn down only by DisposeAsync — a
    /// short-lived join timeout must not silently cap how long an otherwise
    /// healthy connection keeps receiving.
    public async Task ConnectAndJoinAsync(CancellationToken ct)
    {
        _ws = new ClientWebSocket();
        await _ws.ConnectAsync(_uri, ct).ConfigureAwait(false);

        _loopCts = new CancellationTokenSource();
        _receiveLoop = Task.Run(() => ReceiveLoopAsync(_loopCts.Token), CancellationToken.None);

        _joinRef = NextRef();
        var replyTask = RegisterPendingReply(_joinRef);
        await SendTextAsync(EncodeJson([_joinRef, _joinRef, _topic, "phx_join", new object()]), ct)
            .ConfigureAwait(false);

        var reply = await WaitWithTimeoutAsync(replyTask, TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
        string status = reply.TryGetProperty("status", out var s) ? s.GetString() ?? "" : "";
        if (status != "ok")
            throw new InvalidOperationException($"relay refused join on {_topic}: status={status}");

        _heartbeatLoop = Task.Run(() => HeartbeatLoopAsync(_loopCts.Token), CancellationToken.None);
    }

    public async Task SendFrameAsync(byte[] envelope, CancellationToken ct)
    {
        if (_ws is not { State: WebSocketState.Open } || _joinRef is null)
            throw new InvalidOperationException("not connected/joined");

        byte[] wire = PhoenixWireCodec.EncodePush(_joinRef, NextRef(), _topic, "frame", envelope);
        await _sendLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await _ws.SendAsync(wire, WebSocketMessageType.Binary, true, ct).ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    /// Connects, joins, and blocks until the connection drops or ct cancels.
    /// Callers that want a persistent agent should call this in a retry loop
    /// with their own backoff — kept separate so tests can drive one connection
    /// attempt without an unbounded retry wrapper.
    public async Task RunUntilDisconnectedAsync(CancellationToken ct)
    {
        await ConnectAndJoinAsync(ct).ConfigureAwait(false);
        var tasks = new[] { _receiveLoop!, _heartbeatLoop! };
        await Task.WhenAny(tasks).ConfigureAwait(false);
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        var buffer = new byte[8192];
        try
        {
            while (!ct.IsCancellationRequested && _ws!.State == WebSocketState.Open)
            {
                using var ms = new MemoryStream();
                WebSocketReceiveResult result;
                do
                {
                    result = await _ws.ReceiveAsync(buffer, ct).ConfigureAwait(false);
                    if (result.MessageType == WebSocketMessageType.Close) return;
                    ms.Write(buffer, 0, result.Count);
                } while (!result.EndOfMessage);

                var data = ms.ToArray();
                if (result.MessageType == WebSocketMessageType.Binary)
                {
                    HandleBinary(data);
                }
                else
                {
                    HandleText(data);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // normal shutdown
        }
        catch (Exception ex)
        {
            // CONTRACT.md §4: never log anything derived from a frame, on any
            // path including exceptions. ex.Message on a WebSocket/IO failure
            // shouldn't contain frame bytes, but the type name is all we need
            // and carries zero risk of it.
            Diagnostic?.Invoke($"relay receive loop ended: {ex.GetType().Name}");
        }
    }

    private void HandleBinary(byte[] data)
    {
        PhoenixWireCodec.Decoded decoded;
        try
        {
            decoded = PhoenixWireCodec.Decode(data);
        }
        catch (Exception ex)
        {
            // relay/CONTRACT.md: never log frame bytes, even on a malformed frame.
            Diagnostic?.Invoke($"dropped malformed binary relay frame: {ex.GetType().Name}");
            return;
        }

        if (decoded.Kind == 2 /* broadcast */ && decoded.Event == "frame")
        {
            FrameReceived?.Invoke(decoded.Payload);
        }
        else
        {
            Diagnostic?.Invoke("relay: decoded frame did not match broadcast/frame shape, dropping");
        }
    }

    private void HandleText(byte[] data)
    {
        JsonElement[] arr;
        try
        {
            arr = JsonSerializer.Deserialize<JsonElement[]>(data)!;
        }
        catch
        {
            return;
        }
        if (arr.Length < 5) return;

        string? re = arr[1].ValueKind == JsonValueKind.String ? arr[1].GetString() : null;
        string evt = arr[3].GetString() ?? "";
        JsonElement payload = arr[4];

        if (evt == "phx_reply" && re is not null && _pendingReplies.Remove(re, out var tcs))
        {
            JsonElement response = payload.TryGetProperty("response", out var r) ? r : default;
            JsonElement status = payload.TryGetProperty("status", out var st) ? st : default;
            var merged = new Dictionary<string, JsonElement> { ["status"] = status, ["response"] = response };
            tcs.TrySetResult(JsonSerializer.SerializeToElement(merged));
        }
    }

    private async Task HeartbeatLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(HeartbeatInterval, ct).ConfigureAwait(false);
                if (_ws is not { State: WebSocketState.Open }) return;
                string re = NextRef();
                await SendTextAsync(EncodeJson([null, re, "phoenix", "heartbeat", new object()]), ct)
                    .ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // normal shutdown
        }
    }

    private TaskCompletionSource<JsonElement> RegisterPendingReply(string re)
    {
        var tcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingReplies[re] = tcs;
        return tcs;
    }

    private static async Task<JsonElement> WaitWithTimeoutAsync(
        TaskCompletionSource<JsonElement> tcs, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        await using var reg = cts.Token.Register(() => tcs.TrySetCanceled());
        return await tcs.Task.ConfigureAwait(false);
    }

    private async Task SendTextAsync(string json, CancellationToken ct)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        await _sendLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await _ws!.SendAsync(bytes, WebSocketMessageType.Text, true, ct).ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private static string EncodeJson(object?[] arr) => JsonSerializer.Serialize(arr);

    private string NextRef() => Interlocked.Increment(ref _refCounter).ToString();

    public async ValueTask DisposeAsync()
    {
        _loopCts?.Cancel();
        if (_ws is not null)
        {
            try
            {
                if (_ws.State == WebSocketState.Open)
                    await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "shutdown", CancellationToken.None)
                        .ConfigureAwait(false);
            }
            catch
            {
                // best effort
            }
            _ws.Dispose();
        }
        _loopCts?.Dispose();
    }
}
