namespace BatonPass.Windows.Agent;

/// <summary>
/// Every call site in this project must pass a message that is safe to log.
/// Never call this with plaintext, frame bytes, or key material — including
/// from exception messages, which is why catch blocks below log
/// <c>ex.GetType().Name</c> rather than <c>ex.Message</c> wherever the
/// exception could plausibly have captured secret data.
/// </summary>
public static class SafeLog
{
    public static void Info(string message) => Write("INFO", message);
    public static void Warn(string message) => Write("WARN", message);
    public static void Error(string message) => Write("ERROR", message);

    private static void Write(string level, string message) =>
        Console.Error.WriteLine($"{DateTimeOffset.UtcNow:O} [{level}] {message}");
}
