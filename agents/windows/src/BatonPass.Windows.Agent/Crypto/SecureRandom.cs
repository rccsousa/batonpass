using System.Security.Cryptography;

namespace BatonPass.Windows.Agent.Crypto;

/// <summary>
/// CSPRNG draws for nonces, event IDs and keys. SPEC.md §6: "the single most
/// dangerous line in each agent" — a swallowed failure that leaves a nonce
/// buffer all-zero lets an attacker recover the Poly1305 key on reuse.
/// </summary>
public static class SecureRandom
{
    /// <summary>
    /// .NET's RandomNumberGenerator.Fill throws on failure rather than returning
    /// a discardable status code (unlike SecRandomCopyBytes' OSStatus, which the
    /// SPEC warns is commonly ignored). The all-zero check below is the closest
    /// equivalent belt-and-suspenders check: it catches the exact failure shape
    /// SPEC.md names even if some future runtime silently no-ops the fill.
    /// </summary>
    public static byte[] GetBytes(int length)
    {
        var buf = new byte[length];
        RandomNumberGenerator.Fill(buf);
        if (buf.AsSpan().IndexOfAnyExcept((byte)0) < 0)
        {
            throw new CryptographicException(
                $"CSPRNG returned an all-zero {length}-byte buffer; aborting rather than using it.");
        }
        return buf;
    }
}
