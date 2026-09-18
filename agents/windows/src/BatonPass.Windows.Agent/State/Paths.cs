namespace BatonPass.Windows.Agent.State;

/// <summary>
/// On-disk layout. Everything lives under ProgramData, not a roaming user
/// profile path — SPEC.md §6 requires device-local, non-backed-up storage, and
/// a per-app subdirectory created by the agent itself is writable by the
/// creating user without elevation (ProgramData's default ACL grants the
/// creator full control over what it creates; it is HKLM, not ProgramData,
/// that requires admin — which is why the counter anchor below is a second
/// file rather than a registry value).
/// </summary>
public static class Paths
{
    public static string Root =>
        Environment.GetEnvironmentVariable("BATONPASS_STATE_DIR")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "BatonPass");

    public static string Config => Path.Combine(Root, "config.json");
    public static string KeyFile => Path.Combine(Root, "group.key.dpapi");
    public static string DedupState => Path.Combine(Root, "dedup.state.dpapi");

    // Deliberately a different root (LocalAppData, a per-user profile path)
    // rather than under Root (ProgramData): see FileCounterAnchor's doc comment.
    // A backup/restore job scoped to "the BatonPass ProgramData folder" cannot
    // roll this back along with it. Still DPAPI LocalMachine-scoped, so the
    // encryption key is machine-, not user-, held.
    public static string CounterAnchorRoot =>
        Environment.GetEnvironmentVariable("BATONPASS_ANCHOR_DIR")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BatonPass");

    public static string CounterAnchor => Path.Combine(CounterAnchorRoot, "counter.dpapi");
}
