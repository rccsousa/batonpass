using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace BatonPass.Windows.Agent.Native;

/// <summary>
/// Native Win32 clipboard access. Never PowerShell — S3 measured native at 6/6
/// byte-exact against 3/6 for PowerShell, which corrupted emoji, CJK and
/// combining marks while reporting exit code 0 and success.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ClipboardService
{
    // spikes/s3-windows-clipboard/FINDINGS.md: OpenClipboard contention is the
    // classic bug; exponential backoff base 100ms, ~8 attempts clears it.
    private const int MaxAttempts = 8;
    private const int BaseBackoffMs = 100;

    public static int GetSequenceNumber() => NativeMethods.GetClipboardSequenceNumber();

    public static void WriteText(string text)
    {
        WithClipboard(() =>
        {
            if (!NativeMethods.EmptyClipboard())
                throw Win32Error("EmptyClipboard");

            // Both the payload and the three exclusion formats go in this same
            // OpenClipboard/EmptyClipboard session (FINDINGS.md), or Win+V and
            // Cloud Clipboard retain whatever this agent just delivered.
            SetUnicodeText(text);
            SetExclusionFormats();
        });
    }

    public static string? ReadText()
    {
        string? result = null;
        WithClipboard(() =>
        {
            IntPtr h = NativeMethods.GetClipboardData(NativeMethods.CF_UNICODETEXT);
            if (h == IntPtr.Zero) return;

            IntPtr p = NativeMethods.GlobalLock(h);
            if (p == IntPtr.Zero) return;
            try
            {
                result = Marshal.PtrToStringUni(p);
            }
            finally
            {
                NativeMethods.GlobalUnlock(h);
            }
        });
        return result;
    }

    private static void SetUnicodeText(string text)
    {
        int byteCount = (text.Length + 1) * sizeof(char);
        IntPtr hGlobal = NativeMethods.GlobalAlloc(NativeMethods.GMEM_MOVEABLE, (nuint)byteCount);
        if (hGlobal == IntPtr.Zero) throw Win32Error("GlobalAlloc");

        IntPtr target = NativeMethods.GlobalLock(hGlobal);
        if (target == IntPtr.Zero)
        {
            NativeMethods.GlobalFree(hGlobal);
            throw Win32Error("GlobalLock");
        }
        try
        {
            if (text.Length > 0) Marshal.Copy(text.ToCharArray(), 0, target, text.Length);
            Marshal.WriteInt16(target, text.Length * sizeof(char), 0);
        }
        finally
        {
            NativeMethods.GlobalUnlock(hGlobal);
        }

        // Ownership transfers to the system on success; ours to free only if
        // SetClipboardData did not take it.
        if (NativeMethods.SetClipboardData(NativeMethods.CF_UNICODETEXT, hGlobal) == IntPtr.Zero)
        {
            NativeMethods.GlobalFree(hGlobal);
            throw Win32Error("SetClipboardData(CF_UNICODETEXT)");
        }
    }

    private static void SetExclusionFormats()
    {
        // Documented as excluding both history and cloud sync with a NULL data
        // handle — presence of the format is the signal (FINDINGS.md, matches
        // the KeePass/KeePassXC convention this API originates from).
        uint exclude = NativeMethods.RegisterClipboardFormat("ExcludeClipboardContentFromMonitorProcessing");
        NativeMethods.SetClipboardData(exclude, IntPtr.Zero);

        SetDwordFormat("CanIncludeInClipboardHistory", 0);
        SetDwordFormat("CanUploadToCloudClipboard", 0);
    }

    private static void SetDwordFormat(string name, int value)
    {
        uint fmt = NativeMethods.RegisterClipboardFormat(name);
        IntPtr h = NativeMethods.GlobalAlloc(NativeMethods.GMEM_MOVEABLE, (nuint)sizeof(int));
        if (h == IntPtr.Zero) throw Win32Error($"GlobalAlloc({name})");

        IntPtr p = NativeMethods.GlobalLock(h);
        if (p == IntPtr.Zero)
        {
            NativeMethods.GlobalFree(h);
            throw Win32Error($"GlobalLock({name})");
        }
        Marshal.WriteInt32(p, value);
        NativeMethods.GlobalUnlock(h);

        if (NativeMethods.SetClipboardData(fmt, h) == IntPtr.Zero)
        {
            NativeMethods.GlobalFree(h);
            throw Win32Error($"SetClipboardData({name})");
        }
    }

    private static void WithClipboard(Action action)
    {
        for (int attempt = 0; attempt < MaxAttempts; attempt++)
        {
            if (NativeMethods.OpenClipboard(IntPtr.Zero))
            {
                try
                {
                    action();
                }
                finally
                {
                    NativeMethods.CloseClipboard();
                }
                return;
            }

            if (attempt == MaxAttempts - 1)
                throw Win32Error($"OpenClipboard (gave up after {MaxAttempts} attempts)");

            Thread.Sleep(BaseBackoffMs * (1 << attempt)); // 100, 200, 400, ... ms
        }
    }

    private static InvalidOperationException Win32Error(string what) =>
        new($"{what} failed: win32 error {Marshal.GetLastWin32Error()}");
}
