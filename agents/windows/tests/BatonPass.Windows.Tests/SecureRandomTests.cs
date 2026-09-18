using BatonPass.Windows.Agent.Crypto;

namespace BatonPass.Windows.Tests;

public class SecureRandomTests
{
    [Fact]
    public void Returns_the_requested_length()
    {
        Assert.Equal(12, SecureRandom.GetBytes(12).Length);
        Assert.Equal(16, SecureRandom.GetBytes(16).Length);
        Assert.Equal(32, SecureRandom.GetBytes(32).Length);
    }

    [Fact]
    public void Two_draws_are_not_equal()
    {
        // Not a strong randomness test — just a smoke check that this isn't
        // returning a fixed/zeroed buffer.
        var a = SecureRandom.GetBytes(32);
        var b = SecureRandom.GetBytes(32);
        Assert.False(a.AsSpan().SequenceEqual(b));
    }
}
