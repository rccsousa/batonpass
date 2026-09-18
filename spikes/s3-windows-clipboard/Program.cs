using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Linq;
using System.Text.Json;

[assembly: System.Runtime.Versioning.SupportedOSPlatform("windows")]

namespace S3WindowsClipboardProbe;

internal static class Program
{
    private const uint CfUnicodeText = 13;
    private const int RetryCount = 8;
    private const int RetryBaseDelayMs = 100;
    private const uint GmemMoveable = 0x0002;
    private const uint GmemZeroinit = 0x0040;

    private static readonly Encoding Utf8 = new UTF8Encoding(false, true);
    private static readonly Encoding Utf16 = Encoding.Unicode;
    private static readonly int MaxReadChars = 1024 * 1024;

    private static readonly string[] InputsToTest =
    [
        "plain ascii",
        "emoji: 👨‍👩‍👧‍👦",
        "cjk: 漢字かなカナ😀",
        "combining: e\u0301",
        "crlf: line1\r\nline2\r\n",
        "lf: line1\nline2\n"
    ];

    private static readonly string PowerShellScript = @"
$stream = [System.Console]::OpenStandardInput()
$bytes = New-Object System.Collections.Generic.List[byte]
$buf = New-Object byte[] 8192
while (($read = $stream.Read($buf, 0, $buf.Length)) -gt 0) {
    for ($i = 0; $i -lt $read; $i++) { $bytes.Add($buf[$i]) }
}
$text = [System.Text.Encoding]::UTF8.GetString($bytes.ToArray())
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Clipboard]::SetText($text, [System.Windows.Forms.TextDataFormat]::Text)
";

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetClipboardData(uint uFormat, IntPtr hMem);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr GetClipboardData(uint uFormat);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetClipboardSequenceNumber();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalAlloc(uint uFlags, UIntPtr dwBytes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalUnlock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalFree(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetLastError();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ProcessIdToSessionId(uint dwProcessId, out uint sessionId);

    // Exported by kernel32, not wtsapi32, despite the WTS prefix.
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WTSGetActiveConsoleSessionId();

    private record ProbeResult
    {
        public string Name { get; init; } = "";
        public string Status { get; init; } = "";
        public Dictionary<string, object?> Data { get; init; } = [];
    }

    private static int Main(string[] args)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Console.WriteLine("status=unsupported_os payload={\"error\":\"This probe must be run on Windows.\"}");
            return 2;
        }

        Console.OutputEncoding = Utf8;

        // --dump reads the clipboard without writing, so a GUI-origin item
        // (e.g. a Notepad copy) can be inspected before the probe clobbers it.
        if (args.Length > 0 && args[0] == "--dump")
        {
            var text = GetClipboardTextNative();
            var bytes = text is null ? Array.Empty<byte>() : Utf8.GetBytes(text);
            var dump = new
            {
                probe = "s3-clipboard-dump",
                timestampUtc = DateTime.UtcNow.ToString("o"),
                readOk = text is not null,
                charCount = text?.Length ?? 0,
                utf8ByteCount = bytes.Length,
                text,
                utf8Hex = string.Join(" ", bytes.Select(b => b.ToString("X2"))),
                codepoints = text is null
                    ? Array.Empty<string>()
                    : EnumerateCodepoints(text).ToArray()
            };
            Console.WriteLine(JsonSerializer.Serialize(dump, new JsonSerializerOptions { WriteIndented = true }));
            return text is null ? 1 : 0;
        }

        var results = new List<ProbeResult>
        {
            RunNativeRoundTrips(),
            RunPowerShellRoundTrips(),
            RunContentionTest(),
            RunSequenceNumberTest(),
            RunSessionCheck()
        };

        var report = new
        {
            probe = "s3-windows-clipboard",
            target = "windows-pc",
            timestampUtc = DateTimeOffset.UtcNow,
            environment = new Dictionary<string, object?>
            {
                ["machine"] = Environment.MachineName,
                ["processId"] = Environment.ProcessId,
                ["osDescription"] = RuntimeInformation.OSDescription,
                ["is64BitProcess"] = Environment.Is64BitProcess,
                ["userInteractive"] = Environment.UserInteractive,
                ["sessionInfo"] = GetSessionInfo()
            },
            checks = results
        };

        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
        Console.WriteLine(json);
        return results.All(r => r.Status == "PASS" || r.Status == "INCONCLUSIVE") ? 0 : 1;
    }

    private static ProbeResult RunNativeRoundTrips()
    {
        var inputs = new List<Dictionary<string, object?>>();

        foreach (var input in InputsToTest)
        {
            var before = GetClipboardTextNative();
            var status = TrySetTextNative(input, out var setError, out var setElapsedMs);
            var after = GetClipboardTextNative();

            inputs.Add(new Dictionary<string, object?>
            {
                ["input"] = input,
                ["beforeRead"] = before != null,
                ["writeStatus"] = status,
                ["writeErrorCode"] = setError,
                ["writeMs"] = setElapsedMs,
                ["roundTrip"] = string.Equals(input, after),
                ["utf8ByteMatch"] = ByteMatchUtf8(input, after),
                ["readBackSampleHex"] = ToSampleHex(after)
            });
        }

        var allPass = inputs.All(i =>
            (bool)i["roundTrip"]! &&
            (bool)i["utf8ByteMatch"]!);

        return new ProbeResult
        {
            Name = "native_roundtrip_fidelity",
            Status = allPass ? "PASS" : "FAIL",
            Data = new Dictionary<string, object?>
            {
                ["method"] = "OpenClipboard/GetClipboardData/SetClipboardData with retry",
                ["inputs"] = inputs
            }
        };
    }

    private static ProbeResult RunPowerShellRoundTrips()
    {
        var inputs = new List<Dictionary<string, object?>>();

        foreach (var input in InputsToTest)
        {
            var psStatus = RunPowerShellWrite(input, out var psCode, out var psErr);
            var after = GetClipboardTextNative();

            inputs.Add(new Dictionary<string, object?>
            {
                ["input"] = input,
                ["powershellExitCode"] = psCode,
                ["powershellExitError"] = psErr,
                ["powershellStatus"] = psStatus,
                ["roundTrip"] = string.Equals(input, after),
                ["utf8ByteMatch"] = ByteMatchUtf8(input, after),
                ["readBackSampleHex"] = ToSampleHex(after)
            });
        }

        var allPass = inputs.All(i => (bool)i["roundTrip"]! && (bool)i["utf8ByteMatch"]! && (int)i["powershellExitCode"]! == 0);

        return new ProbeResult
        {
            Name = "powershell_roundtrip_fidelity",
            Status = allPass ? "PASS" : "FAIL",
            Data = new Dictionary<string, object?>
            {
                ["method"] = "powershell.exe stdin UTF-8 + System.Windows.Forms.Clipboard.SetText",
                ["inputs"] = inputs
            }
        };
    }

    private static ProbeResult RunContentionTest()
    {
        using var stop = new ManualResetEventSlim(false);
        bool holderOpen = false;

        var holder = new Thread(() =>
        {
            try
            {
                if (!OpenClipboard(IntPtr.Zero))
                    return;
                holderOpen = true;
                stop.Wait();
                CloseClipboard();
            }
            catch (Exception)
            {
                return;
            }
        })
        {
            IsBackground = true
        };
        holder.SetApartmentState(ApartmentState.STA);
        holder.Start();

        SpinWait.SpinUntil(() => holderOpen, TimeSpan.FromSeconds(2));

        var writeSw = Stopwatch.StartNew();
        var writeOk = TrySetTextNative("contention-test", out var writeError, out var writeMs);
        writeSw.Stop();

        stop.Set();
        holder.Join(1000);

        return new ProbeResult
        {
            Name = "contention_retry_behavior",
            Status = writeOk ? "PASS" : "FAIL",
            Data = new Dictionary<string, object?>
            {
                ["method"] = "other thread keeps OpenClipboard open while contender writes",
                ["holderOpen"] = holderOpen,
                ["writeStatus"] = writeOk,
                ["writeErrorCode"] = writeError,
                ["writeMs"] = writeMs,
                ["overallElapsedMs"] = writeSw.ElapsedMilliseconds,
                ["backoffBaseMs"] = RetryBaseDelayMs,
                ["retryCount"] = RetryCount,
                ["resultAfterReleaseMatches"] = string.Equals("contention-test", GetClipboardTextNative())
            }
        };
    }

    private static ProbeResult RunSequenceNumberTest()
    {
        var before = GetClipboardSequenceNumber();
        var write1 = TrySetTextNative("seq-1-" + Guid.NewGuid(), out var e1, out _);
        var mid = GetClipboardSequenceNumber();
        var write2 = TrySetTextNative("seq-2-" + Guid.NewGuid(), out var e2, out _);
        var after = GetClipboardSequenceNumber();

        return new ProbeResult
        {
            Name = "sequence_number_change_detection",
            Status = write1 && write2 && after != before && mid != before && after != mid ? "PASS" : "INCONCLUSIVE",
            Data = new Dictionary<string, object?>
            {
                ["before"] = before,
                ["afterFirstWrite"] = mid,
                ["afterSecondWrite"] = after,
                ["delta1"] = mid >= before ? mid - before : 0,
                ["delta2"] = after >= mid ? after - mid : 0,
                ["write1Ok"] = write1,
                ["write2Ok"] = write2,
                ["write1ErrorCode"] = e1,
                ["write2ErrorCode"] = e2,
                ["readBackExists"] = GetClipboardTextNative() != null
            }
        };
    }

    private static ProbeResult RunSessionCheck()
    {
        var sessionInfo = GetSessionInfo();
        return new ProbeResult
        {
            Name = "interactive_session_required",
            Status = sessionInfo["isInActiveConsoleSession"].Equals(true) ? "PASS" : "INCONCLUSIVE",
            Data = new Dictionary<string, object?>
            {
                ["session"] = sessionInfo,
                ["method"] = "ProcessIdToSessionId vs WTSGetActiveConsoleSessionId",
                ["note"] = "If processSessionId != activeConsoleSessionId, user expects a logged-in interactive session is not active for this process."
            }
        };
    }

    private static Dictionary<string, object> GetSessionInfo()
    {
        ProcessIdToSessionId((uint)Process.GetCurrentProcess().Id, out var processSessionId);
        var activeSessionId = WTSGetActiveConsoleSessionId();

        return new Dictionary<string, object>
        {
            ["processSessionId"] = processSessionId,
            ["activeConsoleSessionId"] = activeSessionId,
            ["isInActiveConsoleSession"] = processSessionId == activeSessionId
        };
    }

    private static bool TrySetTextNative(string text, out int errorCode, out long elapsedMs)
    {
        errorCode = 0;
        elapsedMs = 0;
        var sw = Stopwatch.StartNew();

        for (var attempt = 0; attempt < RetryCount; attempt++)
        {
            if (attempt > 0)
            {
                Thread.Sleep((int)(Math.Pow(2, attempt - 1) * RetryBaseDelayMs));
            }

            if (!OpenClipboard(IntPtr.Zero))
            {
                errorCode = (int)GetLastError();
                continue;
            }

            try
            {
                if (!EmptyClipboard())
                {
                    errorCode = (int)GetLastError();
                    continue;
                }

                var bytes = Utf16.GetBytes(text + "\0");
                var hGlobal = GlobalAlloc(GmemMoveable | GmemZeroinit, (UIntPtr)bytes.Length);
                if (hGlobal == IntPtr.Zero)
                {
                    errorCode = (int)GetLastError();
                    continue;
                }

                var data = GlobalLock(hGlobal);
                if (data == IntPtr.Zero)
                {
                    GlobalFree(hGlobal);
                    errorCode = (int)GetLastError();
                    continue;
                }

                Marshal.Copy(bytes, 0, data, bytes.Length);
                GlobalUnlock(hGlobal);

                if (SetClipboardData(CfUnicodeText, hGlobal) == IntPtr.Zero)
                {
                    errorCode = (int)GetLastError();
                    GlobalFree(hGlobal);
                    continue;
                }

                sw.Stop();
                elapsedMs = sw.ElapsedMilliseconds;
                return true;
            }
            finally
            {
                CloseClipboard();
            }
        }

        sw.Stop();
        elapsedMs = sw.ElapsedMilliseconds;
        return false;
    }

    private static IEnumerable<string> EnumerateCodepoints(string text)
    {
        for (var i = 0; i < text.Length; i++)
        {
            int cp = char.ConvertToUtf32(text, i);
            if (char.IsHighSurrogate(text[i])) i++;
            yield return "U+" + cp.ToString("X4");
        }
    }

    private static string? GetClipboardTextNative()
    {
        if (!OpenClipboard(IntPtr.Zero))
            return null;

        try
        {
            var hData = GetClipboardData(CfUnicodeText);
            if (hData == IntPtr.Zero)
                return null;

            var data = GlobalLock(hData);
            if (data == IntPtr.Zero)
                return null;

            try
            {
                var chars = new char[MaxReadChars];
                var count = 0;
                while (count < chars.Length)
                {
                    var v = (ushort)Marshal.ReadInt16(data, count * 2);
                    if (v == 0)
                        break;
                    chars[count] = (char)v;
                    count++;
                }

                return new string(chars, 0, count);
            }
            finally
            {
                GlobalUnlock(hData);
            }
        }
        finally
        {
            CloseClipboard();
        }
    }

    private static bool RunPowerShellWrite(string text, out int exitCode, out string? stderr)
    {
        using var proc = new Process();
        proc.StartInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NoLogo -NonInteractive -Sta -ExecutionPolicy Bypass -EncodedCommand {Convert.ToBase64String(Encoding.Unicode.GetBytes(PowerShellScript))}",
            RedirectStandardInput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        proc.Start();
        proc.StandardInput.AutoFlush = true;
        var bytes = Utf8.GetBytes(text);
        proc.StandardInput.BaseStream.Write(bytes, 0, bytes.Length);
        proc.StandardInput.Dispose();
        var stderrText = proc.StandardError.ReadToEndAsync();
        proc.WaitForExit(10000);

        stderr = stderrText.Result?.Trim();
        exitCode = proc.ExitCode;
        if (string.IsNullOrWhiteSpace(stderr))
            stderr = null;

        return exitCode == 0;
    }

    private static bool ByteMatchUtf8(string expected, string? actual)
    {
        if (actual is null) return false;
        return Utf8.GetBytes(expected).SequenceEqual(Utf8.GetBytes(actual));
    }

    private static string ToSampleHex(string? value)
    {
        if (value is null) return "";
        var bytes = Utf8.GetBytes(value);
        var count = Math.Min(bytes.Length, 24);
        return string.Join(" ", bytes.Take(count).Select(b => b.ToString("X2")));
    }
}
