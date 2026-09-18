using System.Text;

namespace BatonPass.Windows.Agent.Relay;

/// <summary>
/// Phoenix channel binary sub-protocol (V2 serializer), read directly out of
/// the relay's own dependency source at
/// ../../../../relay/app/deps/phoenix/lib/phoenix/socket/serializers/v2_json_serializer.ex
/// (and its JS mirror, assets/js/phoenix/serializer.js) rather than guessed —
/// relay/CONTRACT.md describes the channel semantics but not this wire layout.
///
/// A push FROM this client (what we send) always carries join_ref, ref, topic
/// and event — 4 one-byte length fields. A push or broadcast FROM the relay TO
/// this client carries no ref (broadcast: no join_ref either) — the two
/// directions are asymmetric and must not share an encoder/decoder.
/// </summary>
public static class PhoenixWireCodec
{
    private const byte KindPush = 0;
    private const byte KindReply = 1;
    private const byte KindBroadcast = 2;

    /// Encodes an outgoing binary push: kind(1) + 4 length bytes + join_ref +
    /// ref + topic + event + payload, matching phoenix.js's binaryEncode.
    public static byte[] EncodePush(string joinRef, string re, string topic, string eventName, ReadOnlySpan<byte> payload)
    {
        byte[] joinRefB = Encoding.UTF8.GetBytes(joinRef);
        byte[] refB = Encoding.UTF8.GetBytes(re);
        byte[] topicB = Encoding.UTF8.GetBytes(topic);
        byte[] eventB = Encoding.UTF8.GetBytes(eventName);

        CheckFieldSize(joinRefB, nameof(joinRef));
        CheckFieldSize(refB, nameof(re));
        CheckFieldSize(topicB, nameof(topic));
        CheckFieldSize(eventB, nameof(eventName));

        int headerLen = 5 + joinRefB.Length + refB.Length + topicB.Length + eventB.Length;
        var buf = new byte[headerLen + payload.Length];
        int o = 0;
        buf[o++] = KindPush;
        buf[o++] = (byte)joinRefB.Length;
        buf[o++] = (byte)refB.Length;
        buf[o++] = (byte)topicB.Length;
        buf[o++] = (byte)eventB.Length;
        joinRefB.CopyTo(buf, o); o += joinRefB.Length;
        refB.CopyTo(buf, o); o += refB.Length;
        topicB.CopyTo(buf, o); o += topicB.Length;
        eventB.CopyTo(buf, o); o += eventB.Length;
        payload.CopyTo(buf.AsSpan(o));
        return buf;
    }

    public readonly record struct Decoded(byte Kind, string? JoinRef, string? Ref, string Topic, string Event, byte[] Payload);

    /// Decodes any binary frame the relay sends us: a broadcast (kind 2, the
    /// normal "someone else pushed a frame" case) or, in principle, a reply or
    /// unsolicited push with a binary payload (kind 0/1 — our channel never
    /// triggers these today, but a client should not crash on the other two
    /// serializer shapes it is technically speaking to).
    public static Decoded Decode(ReadOnlySpan<byte> buffer)
    {
        byte kind = buffer[0];
        return kind switch
        {
            KindBroadcast => DecodeBroadcast(buffer),
            KindPush => DecodePush(buffer),
            KindReply => DecodeReply(buffer),
            _ => throw new FormatException($"unknown Phoenix binary frame kind {kind}"),
        };
    }

    private static Decoded DecodeBroadcast(ReadOnlySpan<byte> buffer)
    {
        int topicSize = buffer[1];
        int eventSize = buffer[2];
        int o = 3;
        string topic = Encoding.UTF8.GetString(buffer.Slice(o, topicSize)); o += topicSize;
        string evt = Encoding.UTF8.GetString(buffer.Slice(o, eventSize)); o += eventSize;
        byte[] payload = buffer[o..].ToArray();
        return new Decoded(KindBroadcast, null, null, topic, evt, payload);
    }

    private static Decoded DecodePush(ReadOnlySpan<byte> buffer)
    {
        int joinRefSize = buffer[1];
        int topicSize = buffer[2];
        int eventSize = buffer[3];
        int o = 4;
        string joinRef = Encoding.UTF8.GetString(buffer.Slice(o, joinRefSize)); o += joinRefSize;
        string topic = Encoding.UTF8.GetString(buffer.Slice(o, topicSize)); o += topicSize;
        string evt = Encoding.UTF8.GetString(buffer.Slice(o, eventSize)); o += eventSize;
        byte[] payload = buffer[o..].ToArray();
        return new Decoded(KindPush, joinRef, null, topic, evt, payload);
    }

    private static Decoded DecodeReply(ReadOnlySpan<byte> buffer)
    {
        int joinRefSize = buffer[1];
        int refSize = buffer[2];
        int topicSize = buffer[3];
        int statusSize = buffer[4];
        int o = 5;
        string joinRef = Encoding.UTF8.GetString(buffer.Slice(o, joinRefSize)); o += joinRefSize;
        string re = Encoding.UTF8.GetString(buffer.Slice(o, refSize)); o += refSize;
        string topic = Encoding.UTF8.GetString(buffer.Slice(o, topicSize)); o += topicSize;
        string status = Encoding.UTF8.GetString(buffer.Slice(o, statusSize)); o += statusSize;
        byte[] payload = buffer[o..].ToArray();
        return new Decoded(KindReply, joinRef, re, topic, status, payload);
    }

    private static void CheckFieldSize(byte[] field, string name)
    {
        if (field.Length > 255)
            throw new ArgumentException($"{name} must be <= 255 UTF-8 bytes for the Phoenix binary frame header");
    }
}
