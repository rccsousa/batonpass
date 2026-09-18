using System.Runtime.Versioning;

namespace BatonPass.Windows.Agent.Native;

public readonly record struct SessionCheck(uint ProcessSessionId, uint ActiveConsoleSessionId)
{
    public bool IsInteractive => ProcessSessionId == ActiveConsoleSessionId;
}

/// <summary>
/// spikes/s3-windows-clipboard/FINDINGS.md: in session 0, native clipboard
/// calls still succeed — writes return success, reads round-trip — against a
/// window-station-local clipboard no user can ever see. Silent void-syncing,
/// not a crash. This must be checked and refused at startup, loudly.
/// </summary>
public static class SessionGuard
{
    [SupportedOSPlatform("windows")]
    public static SessionCheck Check()
    {
        uint pid = NativeMethods.GetCurrentProcessId();
        if (!NativeMethods.ProcessIdToSessionId(pid, out uint processSessionId))
            throw new InvalidOperationException("ProcessIdToSessionId failed for the current process");
        uint activeSessionId = NativeMethods.WTSGetActiveConsoleSessionId();
        return new SessionCheck(processSessionId, activeSessionId);
    }
}
