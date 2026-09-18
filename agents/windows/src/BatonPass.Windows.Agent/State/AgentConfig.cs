using System.Text.Json;
using System.Text.Json.Serialization;

namespace BatonPass.Windows.Agent.State;

/// Non-secret configuration. relay/CONTRACT.md §1: one topic, "clipboard:<group_id>".
public sealed class AgentConfig
{
    // The full Phoenix websocket transport URL, not just the socket mount
    // point — e.g. "ws://100.64.0.10:4000/socket/websocket?vsn=2.0.0", the
    // "/websocket" and "?vsn=2.0.0" are not implicit.
    public required string RelayUri { get; set; }
    public required string GroupId { get; set; }
    public required uint SenderId { get; set; }
    public required uint Epoch { get; set; }

    public static AgentConfig? Load(string path)
    {
        if (!File.Exists(path)) return null;
        return JsonSerializer.Deserialize(File.ReadAllText(path), AgentConfigJsonContext.Default.AgentConfig);
    }

    public void Save(string path)
    {
        string dir = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(dir);
        string json = JsonSerializer.Serialize(this, AgentConfigJsonContext.Default.AgentConfig);
        string tmp = path + ".tmp";
        File.WriteAllText(tmp, json);
        File.Move(tmp, path, overwrite: true);
    }
}

[JsonSerializable(typeof(AgentConfig))]
internal sealed partial class AgentConfigJsonContext : JsonSerializerContext;
