using BatonPass.Windows.Agent.Relay;

namespace BatonPass.Windows.Tests;

/// Confirms the wire layout against the relay's own serializer source
/// (relay/app/deps/phoenix/lib/phoenix/socket/serializers/v2_json_serializer.ex),
/// not a guess: a broadcast decode must match what ClipboardChannel's
/// broadcast_from! actually puts on the wire.
public class PhoenixWireCodecTests
{
    [Fact]
    public void Encoded_push_has_the_expected_byte_layout()
    {
        byte[] payload = [0xAA, 0xBB, 0xCC];
        byte[] wire = PhoenixWireCodec.EncodePush("1", "2", "clipboard:g", "frame", payload);

        Assert.Equal(0, wire[0]); // kind: push
        Assert.Equal(1, wire[1]); // join_ref size
        Assert.Equal(1, wire[2]); // ref size
        Assert.Equal(11, wire[3]); // "clipboard:g".Length
        Assert.Equal(5, wire[4]); // "frame".Length
        Assert.Equal(payload, wire[^payload.Length..]);
    }

    [Fact]
    public void Decodes_a_broadcast_frame_shaped_like_the_relays_fastlane_encoder()
    {
        // Hand-built per Phoenix.Socket.V2.JSONSerializer.fastlane! for a
        // Broadcast with {:binary, data}: <<2, topic_size, event_size, topic, event, data>>.
        string topic = "clipboard:g1";
        string evt = "frame";
        byte[] payload = [1, 2, 3, 4, 5];
        byte[] topicB = System.Text.Encoding.UTF8.GetBytes(topic);
        byte[] eventB = System.Text.Encoding.UTF8.GetBytes(evt);
        byte[] wire = [2, (byte)topicB.Length, (byte)eventB.Length, .. topicB, .. eventB, .. payload];

        var decoded = PhoenixWireCodec.Decode(wire);

        Assert.Equal(topic, decoded.Topic);
        Assert.Equal(evt, decoded.Event);
        Assert.Equal(payload, decoded.Payload);
    }

    [Fact]
    public void Relay_reshaping_a_pushed_envelope_into_a_broadcast_preserves_the_bytes()
    {
        // The client push (kind 0, join_ref+ref+topic+event) and the relay's
        // fan-out (kind 2, topic+event only) are different wire shapes by
        // design (see class doc) — simulate the relay's actual reshape
        // (RelayAppWeb.ClipboardChannel just re-broadcasts the binary payload
        // it received) and confirm the envelope bytes survive untouched
        // (CONTRACT.md §1: the relay moves opaque bytes).
        byte[] envelope = Enumerable.Range(0, 61).Select(i => (byte)i).ToArray();
        string topic = "clipboard:g";
        string evt = "frame";
        byte[] pushed = PhoenixWireCodec.EncodePush("1", "1", topic, evt, envelope);

        // ClipboardChannel.handle_in pattern-matches {:binary, frame} out of the
        // decoded push and calls broadcast_from!(socket, "frame", {:binary, frame})
        // — i.e. it never round-trips through this client's own Decode (a push
        // it sent is not a shape this client ever needs to parse back). What it
        // must preserve is the raw envelope bytes it extracts from the tail of
        // the push frame after the header — reproduce that extraction here.
        int headerLen = 5 + 1 + 1 + topic.Length + evt.Length; // kind+4 sizes+join_ref+ref+topic+event
        byte[] extractedPayload = pushed[headerLen..];
        Assert.Equal(envelope, extractedPayload);

        byte[] topicB = System.Text.Encoding.UTF8.GetBytes(topic);
        byte[] eventB = System.Text.Encoding.UTF8.GetBytes(evt);
        byte[] broadcastWire = [2, (byte)topicB.Length, (byte)eventB.Length, .. topicB, .. eventB, .. extractedPayload];

        var decodedBroadcast = PhoenixWireCodec.Decode(broadcastWire);

        Assert.Equal(envelope, decodedBroadcast.Payload);
        Assert.Equal("clipboard:g", decodedBroadcast.Topic);
        Assert.Equal("frame", decodedBroadcast.Event);
    }
}
