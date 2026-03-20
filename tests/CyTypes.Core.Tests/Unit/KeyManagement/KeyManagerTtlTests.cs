using System.Security.Cryptography;
using CyTypes.Core.KeyManagement;
using FluentAssertions;
using Xunit;

namespace CyTypes.Core.Tests.Unit.KeyManagement;

public sealed class KeyManagerTtlTests
{
    [Fact]
    public void Key_with_TTL_works_within_TTL_window()
    {
        using var km = new KeyManager(TimeSpan.FromSeconds(10));

        var key = km.CurrentKey.ToArray();

        key.Should().HaveCount(32);
        key.Should().NotBeEquivalentTo(new byte[32], "key should not be all zeros");
    }

    [Fact]
    public void Key_with_TTL_throws_KeyExpiredException_after_TTL_expires()
    {
        using var km = new KeyManager(TimeSpan.FromMilliseconds(1));

        Thread.Sleep(50);

        var act = () => { _ = km.CurrentKey.ToArray(); };

        act.Should().Throw<KeyExpiredException>();
    }

    [Fact]
    public void RotateKey_resets_the_TTL_timer()
    {
        using var km = new KeyManager(TimeSpan.FromMilliseconds(1));

        Thread.Sleep(50);

        // Key should be expired now
        km.IsExpired.Should().BeTrue();

        // Rotate resets the timer
        km.RotateKey();

        // Key should be accessible again
        km.IsExpired.Should().BeFalse();
        var key = km.CurrentKey.ToArray();
        key.Should().HaveCount(32);
    }

    [Fact]
    public void IsExpired_is_false_within_TTL_window()
    {
        using var km = new KeyManager(TimeSpan.FromSeconds(10));

        km.IsExpired.Should().BeFalse();
    }

    [Fact]
    public void IsExpired_is_true_after_TTL_expires()
    {
        using var km = new KeyManager(TimeSpan.FromMilliseconds(1));

        Thread.Sleep(50);

        km.IsExpired.Should().BeTrue();
    }

    [Fact]
    public void IsExpired_is_false_when_no_TTL_is_set()
    {
        using var km = new KeyManager();

        km.IsExpired.Should().BeFalse();
    }

    [Fact]
    public void Constructor_with_TTL_validates_TimeSpan_greater_than_zero()
    {
        var actZero = () => new KeyManager(TimeSpan.Zero);
        var actNegative = () => new KeyManager(TimeSpan.FromSeconds(-1));

        actZero.Should().Throw<ArgumentOutOfRangeException>();
        actNegative.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Constructor_TimeSpan_generates_random_key_with_TTL()
    {
        using var km = new KeyManager(TimeSpan.FromMinutes(5));

        km.Ttl.Should().Be(TimeSpan.FromMinutes(5));
        km.CurrentKey.Length.Should().Be(32);
        km.CurrentKey.ToArray().Should().NotBeEquivalentTo(new byte[32]);
    }

    [Fact]
    public void Constructor_ReadOnlySpan_byte_TimeSpan_uses_specified_key_with_TTL()
    {
        var explicitKey = new byte[32];
        RandomNumberGenerator.Fill(explicitKey);

        using var km = new KeyManager(explicitKey, TimeSpan.FromMinutes(5));

        km.Ttl.Should().Be(TimeSpan.FromMinutes(5));
        km.CurrentKey.ToArray().Should().Equal(explicitKey);
    }

    [Fact]
    public void Constructor_ReadOnlySpan_byte_TimeSpan_validates_TimeSpan_greater_than_zero()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        var actZero = () => new KeyManager(key, TimeSpan.Zero);
        var actNegative = () => new KeyManager(key, TimeSpan.FromSeconds(-1));

        actZero.Should().Throw<ArgumentOutOfRangeException>();
        actNegative.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Ttl_property_is_null_when_no_TTL_specified()
    {
        using var km = new KeyManager();

        km.Ttl.Should().BeNull();
    }
}
